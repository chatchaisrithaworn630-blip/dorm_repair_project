package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type User struct {
	ID    int
	Name  string
	Email string
	Role  string
}

type RepairRequest struct {
	ID          int
	UserID      int
	OwnerName   string
	Room        string
	Category    string
	Title       string
	Description string
	Status      string
	CreatedAt   string
}

type Session struct {
	UserID int
	CSRF   string
	Expiry time.Time
}

type LoginAttempt struct {
	Count       int
	BlockedTill time.Time
}

type App struct {
	db            *sql.DB
	sessions      map[string]Session
	loginAttempts map[string]LoginAttempt
	mu            sync.Mutex
	secure        bool
}

type PageData struct {
	Title    string
	User     *User
	CSRF     string
	Error    string
	Success  string
	Message  string
	Requests []RepairRequest
	Request  RepairRequest
	Stats    map[string]int
	Users    []User
}

func main() {
	db, err := sql.Open("sqlite", "dorm.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.SetMaxOpenConns(1)

	if err := initDB(db); err != nil {
		log.Fatal(err)
	}

	// ปรับฐานข้อมูลเดิมให้รองรับสถานะใหม่
	if err := migrateRepairStatus(db); err != nil {
		log.Fatal("Migration repair status failed: ", err)
	}

	app := &App{
		db:            db,
		sessions:      make(map[string]Session),
		loginAttempts: make(map[string]LoginAttempt),
		secure:        strings.EqualFold(os.Getenv("COOKIE_SECURE"), "true"),
	}

	if err := app.createInitialAdmin(); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.home)
	mux.HandleFunc("/register", app.register)
	mux.HandleFunc("/login", app.login)
	mux.HandleFunc("/logout", app.logout)
	mux.HandleFunc("/requests", app.listRequests)
	mux.HandleFunc("/requests/new", app.newRequest)
	mux.HandleFunc("/requests/edit", app.editRequest)
	mux.HandleFunc("/requests/delete", app.deleteRequest)
	mux.HandleFunc("/admin", app.admin)
	mux.HandleFunc("/admin/status", app.adminStatus)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("Dorm Repair started at http://localhost:%s", port)
	log.Fatal(server.ListenAndServe())
}

func initDB(db *sql.DB) error {
	statements := []string{
		`PRAGMA foreign_keys = ON`,
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user'
				CHECK(role IN ('user','admin')),
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS repair_requests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			room TEXT NOT NULL,
			category TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'รอดำเนินการ'
				CHECK(status IN ('รอดำเนินการ','กำลังดำเนินการ','ซ่อมเสร็จ')),
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
	}

	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}

	return nil
}

// migrateRepairStatus ปรับ CHECK constraint ของตารางเดิม
// จากสถานะ "กำลังซ่อม" เป็น "กำลังดำเนินการ"
// และเก็บข้อมูลคำร้องเดิมทั้งหมดไว้
func migrateRepairStatus(db *sql.DB) error {
	var schema string

	err := db.QueryRow(`
		SELECT sql
		FROM sqlite_master
		WHERE type = 'table' AND name = 'repair_requests'
	`).Scan(&schema)

	if err != nil {
		return err
	}

	// ตารางรองรับสถานะใหม่อยู่แล้ว ไม่ต้องสร้างใหม่
	if strings.Contains(schema, "กำลังดำเนินการ") {
		_, err = db.Exec(`
			UPDATE repair_requests
			SET status = 'กำลังดำเนินการ'
			WHERE status = 'กำลังซ่อม'
		`)
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		CREATE TABLE repair_requests_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			room TEXT NOT NULL,
			category TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'รอดำเนินการ'
				CHECK(status IN (
					'รอดำเนินการ',
					'กำลังดำเนินการ',
					'ซ่อมเสร็จ'
				)),
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`
		INSERT INTO repair_requests_new
			(id, user_id, room, category, title, description, status, created_at)
		SELECT
			id,
			user_id,
			room,
			category,
			title,
			description,
			CASE
				WHEN status = 'กำลังซ่อม' THEN 'กำลังดำเนินการ'
				ELSE status
			END,
			created_at
		FROM repair_requests
	`)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`DROP TABLE repair_requests`)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`
		ALTER TABLE repair_requests_new
		RENAME TO repair_requests
	`)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// สร้าง Admin ใหม่ หรืออัปเดตรหัสผ่าน Admin ที่มีอยู่แล้ว
func (a *App) createInitialAdmin() error {
	email := "admin@example.com"
	password := "Admin@123456"

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return err
	}

	var count int
	err = a.db.QueryRow(
		"SELECT COUNT(*) FROM users WHERE email = ?",
		email,
	).Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		_, err = a.db.Exec(
			"UPDATE users SET password_hash = ?, role = 'admin' WHERE email = ?",
			string(hash),
			email,
		)
		if err != nil {
			return err
		}

		log.Printf("Admin password updated for %s", email)
		return nil
	}

	_, err = a.db.Exec(
		"INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')",
		"ผู้ดูแลระบบ",
		email,
		string(hash),
	)
	if err != nil {
		return err
	}

	log.Printf("Initial admin created for %s", email)
	return nil
}
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *App) loginBlocked(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	attempt, exists := a.loginAttempts[key]
	if !exists {
		return false
	}

	if time.Now().Before(attempt.BlockedTill) {
		return true
	}

	if !attempt.BlockedTill.IsZero() {
		delete(a.loginAttempts, key)
	}

	return false
}

func (a *App) recordLoginFailure(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	attempt := a.loginAttempts[key]

	if !attempt.BlockedTill.IsZero() &&
		time.Now().Before(attempt.BlockedTill) {
		return
	}

	attempt.Count++

	if attempt.Count >= 5 {
		attempt.Count = 0
		attempt.BlockedTill = time.Now().Add(5 * time.Minute)
	}

	a.loginAttempts[key] = attempt
}

func (a *App) clearLoginFailures(key string) {
	a.mu.Lock()
	delete(a.loginAttempts, key)
	a.mu.Unlock()
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set(
			"Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'",
		)
		w.Header().Set(
			"Permissions-Policy",
			"camera=(), microphone=(), geolocation=()",
		)

		next.ServeHTTP(w, r)
	})
}

func (a *App) render(w http.ResponseWriter, name string, data PageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmpl, err := template.ParseFiles(
		"templates/layout.html",
		"templates/"+name,
	)
	if err != nil {
		log.Printf("Template parse error (%s): %v", name, err)
		http.Error(w, "Template parse error: "+err.Error(),
			http.StatusInternalServerError)
		return
	}

	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("Template execution error (%s): %v", name, err)
		http.Error(w, "Template execution error: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
}

func (a *App) method(w http.ResponseWriter, r *http.Request, expected string) bool {
	if r.Method != expected {
		w.Header().Set("Allow", expected)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func (a *App) createSession(w http.ResponseWriter, userID int) string {
	tokenBytes := make([]byte, 32)
	csrfBytes := make([]byte, 32)

	if _, err := rand.Read(tokenBytes); err != nil {
		http.Error(w, "ไม่สามารถสร้าง Session ได้", http.StatusInternalServerError)
		return ""
	}

	if _, err := rand.Read(csrfBytes); err != nil {
		http.Error(w, "ไม่สามารถสร้าง CSRF token ได้", http.StatusInternalServerError)
		return ""
	}

	token := hex.EncodeToString(tokenBytes)
	csrf := hex.EncodeToString(csrfBytes)

	a.mu.Lock()
	a.sessions[token] = Session{
		UserID: userID,
		CSRF:   csrf,
		Expiry: time.Now().Add(8 * time.Hour),
	}
	a.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   8 * 60 * 60,
	})

	return token
}

func (a *App) currentUser(r *http.Request) (*User, string) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil, ""
	}

	a.mu.Lock()
	session, ok := a.sessions[cookie.Value]

	if ok && time.Now().After(session.Expiry) {
		delete(a.sessions, cookie.Value)
		ok = false
	}
	a.mu.Unlock()

	if !ok {
		return nil, ""
	}

	var user User
	err = a.db.QueryRow(
		"SELECT id,name,email,role FROM users WHERE id = ?",
		session.UserID,
	).Scan(&user.ID, &user.Name, &user.Email, &user.Role)

	if err != nil {
		return nil, ""
	}

	return &user, session.CSRF
}

func (a *App) requireLogin(w http.ResponseWriter, r *http.Request) (*User, string, bool) {
	user, csrf := a.currentUser(r)

	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, "", false
	}

	return user, csrf, true
}

func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request) (*User, string, bool) {
	user, csrf, ok := a.requireLogin(w, r)
	if !ok {
		return nil, "", false
	}

	if user.Role != "admin" {
		http.Error(w, "ไม่มีสิทธิ์เข้าถึงหน้านี้", http.StatusForbidden)
		return nil, "", false
	}

	return user, csrf, true
}

func (a *App) validCSRF(r *http.Request, expected string) bool {
	got := r.FormValue("csrf")
	return expected != "" && got != "" && got == expected
}

func (a *App) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	user, _ := a.currentUser(r)

	if user != nil {
		if user.Role == "admin" {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/requests", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) register(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.render(w, "register.html", PageData{Title: "สมัครสมาชิก"})
		return
	}

	if !a.method(w, r, http.MethodPost) {
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "ข้อมูลฟอร์มไม่ถูกต้อง", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")

	if len(name) < 2 || len(name) > 80 ||
		!strings.Contains(email, "@") ||
		len(email) > 254 ||
		len(password) < 10 || len(password) > 72 {
		a.render(w, "register.html", PageData{
			Title: "สมัครสมาชิก",
			Error: "กรุณากรอกชื่อ อีเมลให้ถูกต้อง และรหัสผ่าน 10–72 ไบต์",
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "ไม่สามารถบันทึกรหัสผ่านได้", http.StatusInternalServerError)
		return
	}

	_, err = a.db.Exec(
		"INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'user')",
		name,
		email,
		string(hash),
	)
	if err != nil {
		a.render(w, "register.html", PageData{
			Title: "สมัครสมาชิก",
			Error: "อีเมลนี้อาจถูกใช้แล้ว กรุณาตรวจสอบอีกครั้ง",
		})
		return
	}

	http.Redirect(w, r, "/login?registered=1", http.StatusSeeOther)
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		msg := ""
		if r.URL.Query().Get("registered") == "1" {
			msg = "สมัครสมาชิกสำเร็จ กรุณาเข้าสู่ระบบ"
		}

		a.render(w, "login.html", PageData{
			Title:   "เข้าสู่ระบบ",
			Success: msg,
		})
		return
	}

	if !a.method(w, r, http.MethodPost) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10*1024)

	if err := r.ParseForm(); err != nil {
		http.Error(w, "ข้อมูลฟอร์มไม่ถูกต้อง", http.StatusBadRequest)
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")

	key := clientIP(r) + "|" + email

	// ตรวจสอบว่าถูกระงับการเข้าสู่ระบบหรือไม่
	if a.loginBlocked(key) {
		http.Error(
			w,
			"เข้าสู่ระบบผิดหลายครั้ง กรุณารอ 5 นาที",
			http.StatusTooManyRequests,
		)
		return
	}

	var user User
	var hash string

	err := a.db.QueryRow(
		"SELECT id,name,email,role,password_hash FROM users WHERE email = ?",
		email,
	).Scan(&user.ID, &user.Name, &user.Email, &user.Role, &hash)

	if err != nil ||
		bcrypt.CompareHashAndPassword(
			[]byte(hash),
			[]byte(password),
		) != nil {

		// นับจำนวนครั้งที่เข้าสู่ระบบผิด
		a.recordLoginFailure(key)

		// ตรวจซ้ำเพื่อแจ้งเตือนทันทีเมื่อครบ 5 ครั้ง
		if a.loginBlocked(key) {
			http.Error(
				w,
				"เข้าสู่ระบบผิดครบ 5 ครั้ง กรุณารอ 5 นาที",
				http.StatusTooManyRequests,
			)
			return
		}

		a.render(w, "login.html", PageData{
			Title: "เข้าสู่ระบบ",
			Error: "อีเมลหรือรหัสผ่านไม่ถูกต้อง",
		})
		return
	}

	// เข้าสู่ระบบสำเร็จ ล้างจำนวนครั้งที่ผิด
	a.clearLoginFailures(key)

	// ลบ Session เดิมถ้ามี
	if old, err := r.Cookie("session"); err == nil {
		a.mu.Lock()
		delete(a.sessions, old.Value)
		a.mu.Unlock()
	}

	if a.createSession(w, user.ID) == "" {
		return
	}

	if user.Role == "admin" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/requests", http.StatusSeeOther)
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("session")
	if err == nil {
		a.mu.Lock()
		delete(a.sessions, cookie.Value)
		a.mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) listRequests(w http.ResponseWriter, r *http.Request) {
	if !a.method(w, r, http.MethodGet) {
		return
	}

	user, csrf, ok := a.requireLogin(w, r)
	if !ok {
		return
	}

	rows, err := a.db.Query(`
		SELECT id,user_id,room,category,title,description,status,created_at
		FROM repair_requests
		WHERE user_id = ?
		ORDER BY id DESC
	`, user.ID)
	if err != nil {
		http.Error(w, "ไม่สามารถอ่านข้อมูลได้", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var requests []RepairRequest

	for rows.Next() {
		var item RepairRequest
		if err := rows.Scan(
			&item.ID,
			&item.UserID,
			&item.Room,
			&item.Category,
			&item.Title,
			&item.Description,
			&item.Status,
			&item.CreatedAt,
		); err != nil {
			http.Error(w, "ข้อมูลไม่ถูกต้อง", http.StatusInternalServerError)
			return
		}

		requests = append(requests, item)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, "ไม่สามารถอ่านข้อมูลได้", http.StatusInternalServerError)
		return
	}

	a.render(w, "requests.html", PageData{
		Title:    "รายการแจ้งซ่อมของฉัน",
		User:     user,
		CSRF:     csrf,
		Requests: requests,
	})
}

func (a *App) newRequest(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := a.requireLogin(w, r)
	if !ok {
		return
	}

	if r.Method == http.MethodGet {
		a.render(w, "request_form.html", PageData{
			Title: "แจ้งซ่อม",
			User:  user,
			CSRF:  csrf,
		})
		return
	}

	if !a.method(w, r, http.MethodPost) {
		return
	}

	if err := r.ParseForm(); err != nil || !a.validCSRF(r, csrf) {
		http.Error(w, "ข้อมูลฟอร์มไม่ถูกต้องหรือ CSRF token ไม่ถูกต้อง", http.StatusForbidden)
		return
	}

	room := strings.TrimSpace(r.FormValue("room"))
	category := strings.TrimSpace(r.FormValue("category"))
	title := strings.TrimSpace(r.FormValue("title"))
	description := strings.TrimSpace(r.FormValue("description"))

	if len(room) < 1 || len(room) > 20 ||
		!validCategory(category) ||
		len(title) < 3 || len(title) > 120 ||
		len(description) < 5 || len(description) > 2000 {
		a.render(w, "request_form.html", PageData{
			Title: "แจ้งซ่อม",
			User:  user,
			CSRF:  csrf,
			Error: "กรุณาตรวจสอบข้อมูล: หัวข้อ 3–120 ตัวอักษร รายละเอียด 5–2000 ตัวอักษร",
		})
		return
	}

	_, err := a.db.Exec(`
		INSERT INTO repair_requests(user_id,room,category,title,description)
		VALUES(?,?,?,?,?)
	`, user.ID, room, category, title, description)
	if err != nil {
		http.Error(w, "บันทึกคำร้องไม่สำเร็จ", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/requests", http.StatusSeeOther)
}

func validCategory(s string) bool {
	switch s {
	case "ไฟฟ้า", "ประปา", "เครื่องปรับอากาศ", "อุปกรณ์ห้องพัก", "อื่นๆ":
		return true
	}
	return false
}

func (a *App) editRequest(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := a.requireLogin(w, r)
	if !ok {
		return
	}

	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil || id < 1 {
		http.Error(w, "รหัสคำร้องไม่ถูกต้อง", http.StatusBadRequest)
		return
	}

	var item RepairRequest

	err = a.db.QueryRow(`
		SELECT id,user_id,room,category,title,description,status
		FROM repair_requests
		WHERE id = ? AND user_id = ?
	`, id, user.ID).Scan(
		&item.ID,
		&item.UserID,
		&item.Room,
		&item.Category,
		&item.Title,
		&item.Description,
		&item.Status,
	)
	if err != nil {
		http.Error(w, "ไม่พบคำร้องหรือคุณไม่มีสิทธิ์แก้ไข", http.StatusNotFound)
		return
	}

	if r.Method == http.MethodGet {
		a.render(w, "request_form.html", PageData{
			Title:   "แก้ไขคำร้อง",
			User:    user,
			CSRF:    csrf,
			Request: item,
		})
		return
	}

	if !a.method(w, r, http.MethodPost) {
		return
	}

	if err := r.ParseForm(); err != nil || !a.validCSRF(r, csrf) {
		http.Error(w, "ข้อมูลฟอร์มไม่ถูกต้องหรือ CSRF token ไม่ถูกต้อง", http.StatusForbidden)
		return
	}

	room := strings.TrimSpace(r.FormValue("room"))
	category := strings.TrimSpace(r.FormValue("category"))
	title := strings.TrimSpace(r.FormValue("title"))
	description := strings.TrimSpace(r.FormValue("description"))

	if len(room) < 1 || len(room) > 20 ||
		!validCategory(category) ||
		len(title) < 3 || len(title) > 120 ||
		len(description) < 5 || len(description) > 2000 {
		item.Room = room
		item.Category = category
		item.Title = title
		item.Description = description

		a.render(w, "request_form.html", PageData{
			Title:   "แก้ไขคำร้อง",
			User:    user,
			CSRF:    csrf,
			Request: item,
			Error:   "กรุณาตรวจสอบข้อมูลที่กรอก",
		})
		return
	}

	result, err := a.db.Exec(`
		UPDATE repair_requests
		SET room=?,category=?,title=?,description=?
		WHERE id=? AND user_id=? AND status='รอดำเนินการ'
	`, room, category, title, description, id, user.ID)
	if err != nil {
		http.Error(w, "แก้ไขข้อมูลไม่สำเร็จ", http.StatusInternalServerError)
		return
	}

	n, _ := result.RowsAffected()
	if n == 0 {
		http.Error(w, "ไม่พบคำร้อง หรือคำร้องเริ่มดำเนินการแล้วจึงแก้ไขไม่ได้", http.StatusForbidden)
		return
	}

	http.Redirect(w, r, "/requests", http.StatusSeeOther)
}

func (a *App) deleteRequest(w http.ResponseWriter, r *http.Request) {
	if !a.method(w, r, http.MethodPost) {
		return
	}

	user, csrf, ok := a.requireLogin(w, r)
	if !ok {
		return
	}

	if err := r.ParseForm(); err != nil || !a.validCSRF(r, csrf) {
		http.Error(w, "CSRF token ไม่ถูกต้อง", http.StatusForbidden)
		return
	}

	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil || id < 1 {
		http.Error(w, "รหัสคำร้องไม่ถูกต้อง", http.StatusBadRequest)
		return
	}

	result, err := a.db.Exec(`
		DELETE FROM repair_requests
		WHERE id=? AND user_id=? AND status='รอดำเนินการ'
	`, id, user.ID)
	if err != nil {
		http.Error(w, "ลบข้อมูลไม่สำเร็จ", http.StatusInternalServerError)
		return
	}

	n, _ := result.RowsAffected()
	if n == 0 {
		http.Error(w, "ไม่พบคำร้อง หรือคำร้องเริ่มดำเนินการแล้วจึงลบไม่ได้", http.StatusForbidden)
		return
	}

	http.Redirect(w, r, "/requests", http.StatusSeeOther)
}

func (a *App) admin(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}

	rows, err := a.db.Query(`
		SELECT r.id, r.user_id, u.name, r.room,
		       r.category, r.title, r.description,
		       r.status, r.created_at
		FROM repair_requests r
		JOIN users u ON r.user_id = u.id
		ORDER BY r.id DESC
	`)
	if err != nil {
		log.Println("Admin query error:", err)
		http.Error(w, "ไม่สามารถดึงรายการแจ้งซ่อมได้",
			http.StatusInternalServerError)
		return
	}

	var requests []RepairRequest

	for rows.Next() {
		var req RepairRequest

		err := rows.Scan(
			&req.ID,
			&req.UserID,
			&req.OwnerName,
			&req.Room,
			&req.Category,
			&req.Title,
			&req.Description,
			&req.Status,
			&req.CreatedAt,
		)
		if err != nil {
			rows.Close()
			log.Println("Admin scan error:", err)
			http.Error(w, "อ่านรายการแจ้งซ่อมไม่สำเร็จ",
				http.StatusInternalServerError)
			return
		}

		requests = append(requests, req)
	}

	err = rows.Err()
	rows.Close()

	if err != nil {
		log.Println("Admin rows error:", err)
		http.Error(w, "เกิดข้อผิดพลาดในการอ่านข้อมูล",
			http.StatusInternalServerError)
		return
	}

	// นับจำนวนตามสถานะ โดยใช้ชื่อสถานะให้ตรงกัน
	stats := map[string]int{
		"รอดำเนินการ":    0,
		"กำลังดำเนินการ": 0,
		"ซ่อมเสร็จ":      0,
	}

	statsRows, err := a.db.Query(`
		SELECT status, COUNT(*)
		FROM repair_requests
		GROUP BY status
	`)
	if err != nil {
		log.Println("Stats query error:", err)
		http.Error(w, "ไม่สามารถอ่านสถิติได้",
			http.StatusInternalServerError)
		return
	}

	for statsRows.Next() {
		var status string
		var count int

		if err := statsRows.Scan(&status, &count); err != nil {
			statsRows.Close()
			http.Error(w, "อ่านสถิติไม่สำเร็จ",
				http.StatusInternalServerError)
			return
		}

		stats[status] = count
	}

	err = statsRows.Err()
	statsRows.Close()

	if err != nil {
		http.Error(w, "อ่านสถิติไม่สำเร็จ",
			http.StatusInternalServerError)
		return
	}

	a.render(w, "admin.html", PageData{
		Title:    "จัดการรายการแจ้งซ่อม",
		User:     user,
		CSRF:     csrf,
		Requests: requests,
		Stats:    stats,
	})
}

func (a *App) adminStatus(w http.ResponseWriter, r *http.Request) {
	if !a.method(w, r, http.MethodPost) {
		return
	}

	_, csrf, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}

	if err := r.ParseForm(); err != nil ||
		!a.validCSRF(r, csrf) {
		http.Error(w, "CSRF token ไม่ถูกต้อง", http.StatusForbidden)
		return
	}

	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil || id < 1 {
		http.Error(w, "รหัสรายการไม่ถูกต้อง", http.StatusBadRequest)
		return
	}

	status := r.FormValue("status")

	switch status {
	case "รอดำเนินการ", "กำลังดำเนินการ", "ซ่อมเสร็จ":
		// สถานะถูกต้อง
	default:
		http.Error(w, "สถานะไม่ถูกต้อง", http.StatusBadRequest)
		return
	}

	result, err := a.db.Exec(
		"UPDATE repair_requests SET status = ? WHERE id = ?",
		status,
		id,
	)
	if err != nil {
		log.Println("Update status error:", err)
		http.Error(w, "บันทึกสถานะไม่สำเร็จ",
			http.StatusInternalServerError)
		return
	}

	affected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, "ตรวจสอบผลการบันทึกไม่สำเร็จ",
			http.StatusInternalServerError)
		return
	}

	if affected == 0 {
		http.Error(w, "ไม่พบรายการแจ้งซ่อม", http.StatusNotFound)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
