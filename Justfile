export RISC0_DEV_MODE := "1"
export PATH := "/Users/soloking/.risc0/bin:" + env_var("PATH")

build:
    cargo build --workspace

test:
    RISC0_DEV_MODE=1 cargo test --workspace

test-registration:
    RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test registration

test-membership:
    RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test membership_proof

test-moderation:
    RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test moderation_cert

test-slash:
    RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test slash

test-e2e:
    RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test e2e

clippy:
    RISC0_SKIP_BUILD=1 cargo clippy --workspace -- -D warnings

audit:
    cargo audit

app-dev:
    cd app && npm install && npm run dev

keygen:
    RISC0_DEV_MODE=1 ./target/debug/forum-anon keygen --out /tmp/test.key

clean:
    cargo clean
