package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"syscall"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

type User struct {
	ID       int
	Username string
	Password string
}

type Account struct {
	ID       int
	Account  string
	Password string
}

const (
	MinCost     int = 4  // the minimum allowable cost as passed in to GenerateFromPassword
	MaxCost     int = 31 // the maximum allowable cost as passed in to GenerateFromPassword
	DefaultCost int = 10 // the cost that will actually be set if a cost below MinCost is passed into GenerateFromPassword
)

func getAllRecords(db *sql.DB) []User {
	rows, err := db.Query("SELECT id, username, password FROM users")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err = rows.Scan(&user.ID, &user.Username, &user.Password)
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, user)
	}

	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}

	return users
}

func createUser(userMap map[string]int, db *sql.DB) {
	var username []byte
	var password []byte
	fmt.Print("Enter a username: ")
	fmt.Scanln(&username)
	fmt.Print("Enter a passphrase: ")
	hiddenPwd, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println(err)
		return
	}
	passwordDigest, err := bcrypt.GenerateFromPassword(hiddenPwd, DefaultCost)
	if err != nil {
		fmt.Println(err)
		return
	}
	password = passwordDigest

	insertUserSQL := `INSERT INTO users (username, password) VALUES (?, ?)`
	_, err = db.Exec(insertUserSQL, string(username), string(password))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\n\n")

	users := getAllRecords(db)
	for _, v := range users {
		fmt.Printf("ID:%v, USERNAME: %v, PASSWORD: %v\n", v.ID, v.Username, v.Password)
	}
	menu(true, userMap, db)
}

func authenticateUser(username string, password string, db *sql.DB) bool {

	row := db.QueryRow("SELECT * FROM users WHERE username = ?", username)
	var id int
	var usrname, pwd string

	// Scan the result into the variables
	err := row.Scan(&id, &usrname, &pwd)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println("No user found with that username.")
		} else {
			fmt.Println(err)
		}
		return false
	}

	success := bcrypt.CompareHashAndPassword([]byte(pwd), []byte(password))

	if success == nil {
		return true
	} else {
		return false
	}
}

func menu(status bool, userMap map[string]int, db *sql.DB) {
	i := status
	for i {
		var username string
		var password string
		fmt.Println("Type \"!create to create a new user account.")
		fmt.Println("Type \"!list to list all user accounts.")
		fmt.Print("Enter username: ")
		fmt.Scanln(&username)

		// If create:
		if strings.Contains(username, "!create") {
			i = false
			createUser(userMap, db)
		} else if strings.Contains(username, "!list") {
			users := getAllRecords(db)
			for _, v := range users {
				fmt.Printf("ID:%v, USERNAME: %v, PASSWORD: %v\n", v.ID, v.Username, v.Password)
			}
		} else {
			_, ok := userMap[username]
			if ok {
				fmt.Println("EXISTS")
				fmt.Print("Enter password: ")
				fmt.Scanln(&password)
				if authenticateUser(username, password, db) {
					fmt.Println("LOGIN SUCCESSFUL.")
					loggedIn(username, password)
				} else {
					fmt.Println("INVALID CREDENTIALS.")
				}
			} else {
				fmt.Println("DOESNT EXISTS")
			}
		}
	}
}

func getMD5Hash(text string) string {
	hasher := md5.New()
	io.WriteString(hasher, text)
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func loggedIn(username string, password string) {
	fmt.Printf("Logged in as: %v\n", username)
	tableName := getMD5Hash(username + password)
	dbFileName := fmt.Sprintf("%v.db", tableName)
	var db *sql.DB
	var err error
	// Check if the database file exists
	if _, err := os.Stat(dbFileName); os.IsNotExist(err) {
		fmt.Println("Database does not exist, creating a new one.")
		dsn := fmt.Sprintf("file:%v?_pragma_key=%s&_pragma_cipher_page_size=4096", dbFileName, password)
		db, err = sql.Open("sqlite3", dsn)
		if err != nil {
			fmt.Println("ERROR 1")
			panic(err)
		}
		defer db.Close()

		// Create your tables and initialize the database here
		// Example: db.Exec("CREATE TABLE IF NOT EXISTS ...")
	} else {
		fmt.Println("Database already exists.")
		// Open the database with the password

		db, err = sql.Open("sqlite3", fmt.Sprintf("file:%v.db?mode=rw&_pragma_key=%v&_pragma_cipher_page_size=4096", tableName, password))
		if err != nil {
			fmt.Println("Error opening database:", err)
			return
		}
		defer db.Close()
	}

	// Use the database as usual
	_, err = db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%v` (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, account TEXT,password TEXT)", tableName))
	if err != nil {
		fmt.Println("ERROR 2")
		panic(err)
	}

	encryptFile(dbFileName, []byte(password))
	userMenu(db, username, tableName, dbFileName)

}

func viewAccounts(db *sql.DB, table string) []Account {
	rows, err := db.Query(fmt.Sprintf("SELECT id, account, password FROM %v", table))
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var accounts []Account
	for rows.Next() {
		var account Account
		err = rows.Scan(&account.ID, &account.Account, &account.Password)
		if err != nil {
			log.Fatal(err)
		}
		accounts = append(accounts, account)
	}

	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}

	return accounts
}

func createAccountRecord(db *sql.DB, table string) {
	var accountName string
	var accountPassword string
	fmt.Print("Enter the Account Name: ")
	fmt.Scanln(&accountName)
	fmt.Print("Enter the Account Password: ")
	fmt.Scanln(&accountPassword)

	insertAccountSQL := fmt.Sprintf(`INSERT INTO %v (account, password) VALUES (?, ?)`, table)
	_, err := db.Exec(insertAccountSQL, accountName, accountPassword)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nAccount successfully created for %v\n", accountName)
}

func encryptFile(filename string, key []byte) error {
	plaintext, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return os.WriteFile(filename+".enc", ciphertext, 0644)
}

func decryptFile(filename string, key []byte) error {
	ciphertext, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	return os.WriteFile(filename+".dec", plaintext, 0644)
}

func userMenu(db *sql.DB, username string, table string, file string) {

	for {
		var option string
		fmt.Println("Options: !viewAccounts, !createAccount, !deleteAccount, !showPassword")
		fmt.Print("Enter option: ")
		fmt.Scanln(&option)
		switch option {
		case "!viewAccounts":
			accounts := viewAccounts(db, table)
			for _, v := range accounts {
				fmt.Printf("ID: %v | Account: %v | Password: %v\n", v.ID, v.Account, v.Password)
			}
		case "!createAccount":
			fmt.Println("work1")
			createAccountRecord(db, table)
		case "!deleteAccount":
			fmt.Println("work2")
		case "!showPassword":
			fmt.Println("work3")
		default:
			fmt.Println("work4")
		}
	}
}

func main() {
	db, err := sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Open User Database, Create if not exist
	createTableSQL := `CREATE TABLE IF NOT EXISTS users (
		"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,		
		"username" TEXT,
		"password" TEXT
	);`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatal(err)
	}

	users := getAllRecords(db)
	userMap := make(map[string]int)
	for i, v := range users {
		userMap[v.Username] = i
	}

	menu(true, userMap, db)
}
