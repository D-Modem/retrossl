module github.com/D-Modem/retrossl

go 1.26.0

// The export cipher suites' temporary RSA keys are 512 bits, which Go
// refuses without this.  Programs that use the package need it too.
godebug rsa1024min=0
