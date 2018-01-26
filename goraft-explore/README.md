# goraft-explore

Exploring raft consensus algorithm using Go.

# exploring

```
$ ./goraft-explore -id 1 -cluster "http://127.0.0.1:9021,http://127.0.0.1:9022,http://127.0.0.1:9023" -port 9021 -join
$ ./goraft-explore -id 2 -cluster "http://127.0.0.1:9021,http://127.0.0.1:9022,http://127.0.0.1:9023" -port 9022 -join
$ ./goraft-explore -id 3 -cluster "http://127.0.0.1:9021,http://127.0.0.1:9022,http://127.0.0.1:9023" -port 9023 -join

```