    A[Start Verification] --> B{All Hashes Match?}
    B -->|No| C[Mark Invalid]
    B -->|Yes| D{All Signatures Valid?}
    D -->|No| C
    D -->|Yes| E{Product Recalled?}
    E -->|Yes| C
    E -->|No| F[Mark Valid]