---
name: go-testing
description: Unit and integration test patterns for the Go server
confidence: 90
scope:
  - "internal/**/*_test.go"
---

# Testing Convention

## Rules

1. Test files live in the same package as the code under test (`package user`, not `package user_test`). This allows testing unexported functions.
2. Test function naming follows `Test{FunctionName}_{Scenario}` where scenario uses `Should` phrasing: `TestGenerateChallenge_ShouldGenerateUniqueChallenge`, `TestExtractJWSFromAuthorizationHeader_ShouldFailWithInvalidFormat`.
3. Prefer multiple separate top-level test functions over subtests with `t.Run(...)`. Only use `t.Run` when truly parameterized table-driven tests are needed.
4. Test structure uses `// given`, `// when`, `// then` comments (BDD-style) to separate setup, action, and assertion.
5. Use `github.com/stretchr/testify/assert` for assertions. Never use raw `t.Errorf` / `t.Fatalf` except in the `keys` package which uses stdlib testing style (both are acceptable).
6. Mock repositories are hand-written structs in the test file implementing the repository interface. No mock generation libraries. Mock structs track calls for assertion (e.g. `updateRoleCalls []struct{...}`).
7. Mock constructors are `newMock{Type}()` (unexported, camelCase).
8. Integration tests are tagged with `//go:build integration` and live in `*_integration_test.go` files. They require a real database. Run with `go test -tags=integration ./internal/... . -p 1` (see CLAUDE.md Quick Commands for why).
9. Unit tests have no build tags and run with `go test ./internal/... .` (see CLAUDE.md Quick Commands for why not `./...`).
10. Tests for pure functions (crypto, parsing) may use stdlib `t.Fatalf` / `t.Errorf` style directly.
11. Do not test repository SQL directly in unit tests — use hand-written mocks. Integration tests cover actual SQL behaviour.
12. `timeNowFunc` is a package-level variable in `user.go` (`var timeNowFunc = time.Now`) allowing tests to inject a fixed time for TTL/expiry testing.

## Example

```go
// Unit test — same package, given/when/then, testify assertions
package user

func TestExtractJWSFromAuthorizationHeader_ShouldExtractValidly(t *testing.T) {
    // given
    authHeader := "Bearer eyJhbGci..."

    // when
    jws, err := extractJWSFromAuthorizationHeader(authHeader)

    // then
    assert.NoError(t, err)
    assert.NotEmpty(t, jws)
}

// Hand-written mock repository
type mockUserRepository struct {
    users           map[string]*User
    updateRoleCalls []struct{ publicKey, role string }
}

func newMockUserRepository() *mockUserRepository {
    return &mockUserRepository{users: make(map[string]*User)}
}

func (m *mockUserRepository) CreateUser(user *User) error {
    if _, exists := m.users[user.PublicKey]; exists {
        return fmt.Errorf("user already exists")
    }
    m.users[user.PublicKey] = user
    return nil
}
```

## Anti-pattern

```go
// WRONG: test in external package without good reason
package user_test  // use package user for access to unexported identifiers

// WRONG: t.Run for non-table-driven cases
func TestSomething(t *testing.T) {
    t.Run("scenario1", func(t *testing.T) { ... })
    t.Run("scenario2", func(t *testing.T) { ... })
    // prefer: two separate TestSomething_Scenario1 and TestSomething_Scenario2

// WRONG: using a mock generation library
//go:generate mockgen ...

// WRONG: missing given/when/then structure
func TestFoo(t *testing.T) {
    result, err := doThing("input")  // no structure comments
    assert.NoError(t, err)
}
```

## Scope

- `internal/**/*_test.go`
