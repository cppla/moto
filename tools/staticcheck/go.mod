module moto/tools/staticcheck

go 1.27.2

tool honnef.co/go/tools/cmd/staticcheck

require (
	github.com/BurntSushi/toml v1.4.1-0.20240526193622-a339e1f7089c // indirect
	golang.org/x/exp/typeparams v0.0.0-20231108232855-2478ac86f678 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	// Go 1.27 uses unified export format v5. Staticcheck's default x/tools
	// dependency predates that format; pin the compatible importer here.
	golang.org/x/tools v0.51.0 // indirect
	honnef.co/go/tools v0.8.1 // indirect
)
