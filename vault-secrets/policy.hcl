path "secret/*" {
  capabilities = ["create"]
}

path "secret/foo" {
  capabilities = ["read"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
