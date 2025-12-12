sequenceDiagram
    autonumber
    participant Parent
    participant System
    participant Child

    Note over Parent: Normal Execution

    Parent->>Parent: keysinuse_atfork_prepare()
    Parent->>Parent: LOCK EVERYTHING (Mutex + RWLocks)
    
    Parent->>System: fork()
    
    System->>Child: Copy Memory (Locks are LOCKED)
    
    par Parent Resume
        Parent->>Parent: keysinuse_atfork_parent()
        Parent->>Parent: UNLOCK EVERYTHING
        Note over Parent: Continues...
    and Child Resume
        Child->>Child: keysinuse_atfork_child()
        Note right of Child: Cannot unlock RWLocks (Wrong Owner)
        Child->>Child: DESTROY Old RWLocks
        Child->>Child: CREATE New RWLocks
        Child->>Child: UNLOCK Mutex
        Child->>Child: Start New Logging Thread
        sequenceDiagram
    autonumber
    participant Parent
    participant System
    participant Child

    Note over Parent: Normal Execution

    Parent->>Parent: keysinuse_atfork_prepare()
    Parent->>Parent: LOCK EVERYTHING (Mutex + RWLocks)
    
    Parent->>System: fork()
    
    System->>Child: Copy Memory (Locks are LOCKED)
    
    par Parent Resume
        Parent->>Parent: keysinuse_atfork_parent()
        Parent->>Parent: UNLOCK EVERYTHING
        Note over Parent: Continues...
    and Child Resume
        Child->>Child: keysinuse_atfork_child()
        Note right of Child: Cannot unlock RWLocks (Wrong Owner)
        Child->>Child: DESTROY Old RWLocks
        Child->>Child: CREATE New RWLocks
        Child->>Child: UNLOCK Mutex
        Child->>Child: Start New Logging Thread
end