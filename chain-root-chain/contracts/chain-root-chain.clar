;; ChainRootChain - Privacy-Preserving Identity and Skill Verification Platform
;; A decentralized platform for verifiable skill attestations with privacy preservation

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-unauthorized (err u103))
(define-constant err-insufficient-stake (err u104))
(define-constant err-invalid-skill (err u105))
(define-constant err-expired (err u106))

;; Minimum stake required to become a validator (in microSTX)
(define-constant min-validator-stake u1000000)

;; Data Variables
(define-data-var platform-active bool true)
(define-data-var total-validators uint u0)
(define-data-var total-skills uint u0)

;; Data Maps

;; User identity profiles (privacy-preserving)
(define-map user-profiles
    principal
    {
        profile-hash: (buff 32),
        created-at: uint,
        active: bool
    }
)

;; Skill definitions
(define-map skills
    uint ;; skill-id
    {
        name: (string-ascii 64),
        category: (string-ascii 32),
        prerequisite-id: (optional uint),
        creator: principal,
        created-at: uint,
        active: bool
    }
)

;; Skill attestations with privacy preservation
(define-map skill-attestations
    {user: principal, skill-id: uint}
    {
        proof-hash: (buff 32),
        validated-by: (list 5 principal),
        validation-count: uint,
        attestation-date: uint,
        expiry-date: uint,
        active: bool
    }
)

;; Validator registry
(define-map validators
    principal
    {
        stake-amount: uint,
        reputation-score: uint,
        validated-count: uint,
        registered-at: uint,
        active: bool
    }
)

;; Validator stakes
(define-map validator-stakes
    principal
    uint
)

;; Skill validation requirements
(define-map skill-validation-config
    uint ;; skill-id
    {
        min-validators: uint,
        decay-period: uint ;; blocks until skill needs revalidation
    }
)

;; Public Functions

;; Register a new user profile
(define-public (register-user (profile-hash (buff 32)))
    (let
        (
            (caller tx-sender)
        )
        (asserts! (is-eq (var-get platform-active) true) err-unauthorized)
        (asserts! (is-none (map-get? user-profiles caller)) err-already-exists)
        
        (ok (map-set user-profiles caller {
            profile-hash: profile-hash,
            created-at: block-height,
            active: true
        }))
    )
)

;; Register as a validator with stake
(define-public (register-validator (stake-amount uint))
    (let
        (
            (caller tx-sender)
        )
        (asserts! (is-eq (var-get platform-active) true) err-unauthorized)
        (asserts! (>= stake-amount min-validator-stake) err-insufficient-stake)
        (asserts! (is-none (map-get? validators caller)) err-already-exists)
        
        ;; Transfer stake to contract
        (try! (stx-transfer? stake-amount caller (as-contract tx-sender)))
        
        ;; Register validator
        (map-set validators caller {
            stake-amount: stake-amount,
            reputation-score: u100,
            validated-count: u0,
            registered-at: block-height,
            active: true
        })
        
        (map-set validator-stakes caller stake-amount)
        (var-set total-validators (+ (var-get total-validators) u1))
        (ok true)
    )
)

;; Create a new skill definition
(define-public (create-skill 
    (name (string-ascii 64))
    (category (string-ascii 32))
    (prerequisite-id (optional uint))
    (min-validators uint)
    (decay-period uint))
    (let
        (
            (skill-id (+ (var-get total-skills) u1))
        )
        (asserts! (is-eq (var-get platform-active) true) err-unauthorized)
        
        ;; Verify prerequisite exists if specified
        (match prerequisite-id
            prereq-id (asserts! (is-some (map-get? skills prereq-id)) err-invalid-skill)
            true
        )
        
        ;; Create skill
        (map-set skills skill-id {
            name: name,
            category: category,
            prerequisite-id: prerequisite-id,
            creator: tx-sender,
            created-at: block-height,
            active: true
        })
        
        ;; Set validation requirements
        (map-set skill-validation-config skill-id {
            min-validators: min-validators,
            decay-period: decay-period
        })
        
        (var-set total-skills skill-id)
        (ok skill-id)
    )
)

;; Attest to a user's skill (validator function)
(define-public (attest-skill 
    (user principal)
    (skill-id uint)
    (proof-hash (buff 32)))
    (let
        (
            (caller tx-sender)
            (validator-info (unwrap! (map-get? validators caller) err-unauthorized))
            (skill-info (unwrap! (map-get? skills skill-id) err-not-found))
            (config (unwrap! (map-get? skill-validation-config skill-id) err-not-found))
            (existing-attestation (map-get? skill-attestations {user: user, skill-id: skill-id}))
        )
        (asserts! (is-eq (var-get platform-active) true) err-unauthorized)
        (asserts! (get active validator-info) err-unauthorized)
        (asserts! (is-some (map-get? user-profiles user)) err-not-found)
        (asserts! (get active skill-info) err-invalid-skill)
        
        (match existing-attestation
            attestation
            ;; Update existing attestation
            (let
                (
                    (current-validators (get validated-by attestation))
                    (new-validators (unwrap-panic (as-max-len? (append current-validators caller) u5)))
                )
                (map-set skill-attestations {user: user, skill-id: skill-id} {
                    proof-hash: proof-hash,
                    validated-by: new-validators,
                    validation-count: (+ (get validation-count attestation) u1),
                    attestation-date: (get attestation-date attestation),
                    expiry-date: (+ block-height (get decay-period config)),
                    active: true
                })
                
                ;; Update validator stats
                (map-set validators caller 
                    (merge validator-info {validated-count: (+ (get validated-count validator-info) u1)})
                )
                (ok true)
            )
            ;; Create new attestation
            (begin
                (map-set skill-attestations {user: user, skill-id: skill-id} {
                    proof-hash: proof-hash,
                    validated-by: (list caller),
                    validation-count: u1,
                    attestation-date: block-height,
                    expiry-date: (+ block-height (get decay-period config)),
                    active: true
                })
                
                ;; Update validator stats
                (map-set validators caller 
                    (merge validator-info {validated-count: (+ (get validated-count validator-info) u1)})
                )
                (ok true)
            )
        )
    )
)

;; Verify a skill attestation
(define-public (verify-skill-attestation
    (user principal)
    (skill-id uint)
    (proof-hash (buff 32)))
    (let
        (
            (attestation (unwrap! (map-get? skill-attestations {user: user, skill-id: skill-id}) err-not-found))
            (config (unwrap! (map-get? skill-validation-config skill-id) err-not-found))
        )
        (asserts! (get active attestation) err-expired)
        (asserts! (< block-height (get expiry-date attestation)) err-expired)
        (asserts! (is-eq (get proof-hash attestation) proof-hash) err-unauthorized)
        (asserts! (>= (get validation-count attestation) (get min-validators config)) err-unauthorized)
        
        (ok {
            verified: true,
            validation-count: (get validation-count attestation),
            attestation-date: (get attestation-date attestation),
            expiry-date: (get expiry-date attestation)
        })
    )
)

;; Withdraw validator stake
(define-public (withdraw-stake)
    (let
        (
            (caller tx-sender)
            (validator-info (unwrap! (map-get? validators caller) err-not-found))
            (stake-amount (get stake-amount validator-info))
        )
        (asserts! (get active validator-info) err-unauthorized)
        
        ;; Deactivate validator
        (map-set validators caller (merge validator-info {active: false}))
        
        ;; Return stake
        (try! (as-contract (stx-transfer? stake-amount tx-sender caller)))
        (map-delete validator-stakes caller)
        
        (ok stake-amount)
    )
)

;; Read-only functions

;; Get user profile
(define-read-only (get-user-profile (user principal))
    (map-get? user-profiles user)
)

;; Get skill info
(define-read-only (get-skill-info (skill-id uint))
    (map-get? skills skill-id)
)

;; Get skill attestation
(define-read-only (get-skill-attestation (user principal) (skill-id uint))
    (map-get? skill-attestations {user: user, skill-id: skill-id})
)

;; Get validator info
(define-read-only (get-validator-info (validator principal))
    (map-get? validators validator)
)

;; Check if skill is verified
(define-read-only (is-skill-verified (user principal) (skill-id uint))
    (match (map-get? skill-attestations {user: user, skill-id: skill-id})
        attestation
        (let
            (
                (config (unwrap! (map-get? skill-validation-config skill-id) (ok false)))
            )
            (ok (and 
                (get active attestation)
                (< block-height (get expiry-date attestation))
                (>= (get validation-count attestation) (get min-validators config))
            ))
        )
        (ok false)
    )
)

;; Get platform statistics
(define-read-only (get-platform-stats)
    (ok {
        total-validators: (var-get total-validators),
        total-skills: (var-get total-skills),
        active: (var-get platform-active)
    })
)

;; Admin functions

;; Toggle platform active status
(define-public (toggle-platform-status)
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (var-set platform-active (not (var-get platform-active)))
        (ok (var-get platform-active))
    )
)
