package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"

	_ "github.com/mattn/go-sqlite3"
)

const (
	dbPassword = "p7Kx9mN2vQ8rL4wZ6tY1cE5bH3sF0gA"
	apiKey     = "sk-proj-9xKmT4pL2vN8qR6wC3zY1hJ5bG7fD0sA4eU9iO2kM6nP8tQ1rV3xW5yH7"
)

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.Exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
	db.Exec("INSERT INTO users (username, password) VALUES ('admin', 'p7Kx9mN2vQ8rL4wZ6tY1cE5bH3sF0gA')")

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/file", fileHandler)
	http.HandleFunc("/user", userHandler)
	http.HandleFunc("/health", healthHandler)

	fmt.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Vulnerable Go Web Server\n")
	fmt.Fprintf(w, "Endpoints:\n")
	fmt.Fprintf(w, "  /ping?host=<hostname>  - Ping a host\n")
	fmt.Fprintf(w, "  /file?path=<filepath>  - Read a file\n")
	fmt.Fprintf(w, "  /user?name=<username>  - Get user info\n")
	fmt.Fprintf(w, "  /health                - Health check\n")
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		fmt.Fprintf(w, "Usage: /ping?host=<hostname>\n")
		return
	}

	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(w, "Error: %v\n", err)
	}
	fmt.Fprintf(w, "Output:\n%s\n", output)
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
	filepath := r.URL.Query().Get("path")
	if filepath == "" {
		fmt.Fprintf(w, "Usage: /file?path=<filepath>\n")
		return
	}

	content, err := os.ReadFile(filepath)
	if err != nil {
		fmt.Fprintf(w, "Error reading file: %v\n", err)
		return
	}
	fmt.Fprintf(w, "File contents:\n%s\n", content)
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("name")
	if username == "" {
		fmt.Fprintf(w, "Usage: /user?name=<username>\n")
		return
	}

	query := "SELECT username, password FROM users WHERE username = '" + username + "'"
	rows, err := db.Query(query)
	if err != nil {
		fmt.Fprintf(w, "Database error: %v\n", err)
		return
	}
	defer rows.Close()

	fmt.Fprintf(w, "Query: %s\n\n", query)
	for rows.Next() {
		var user, pass string
		rows.Scan(&user, &pass)
		fmt.Fprintf(w, "User: %s, Password: %s\n", user, pass)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "API Key: %s\n", apiKey)
	fmt.Fprintf(w, "DB Password: %s\n", dbPassword)
	fmt.Fprintf(w, "Status: OK\n")
	fmt.Fprintf(w, "Environment: %s\n", os.Getenv("ENV"))
}
