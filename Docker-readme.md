# Go to project
cd pcapcat

# Build image
```bash
docker build -t pcapcat:latest . 
```

# Folder structure
```
pcapcat/
├── app/
│   ├── cli.py         # CLI entrypoint (scan/search commands)
│   ├── db.py
│   ├── ...
├── data/
│   ├── pcaps/         # pcap files to scan
│   └── index.db       # SQLite index file
├── requirements.txt
├── Dockerfile
└── DOCKER-README.md
```


# Run for example: Scan for pcaps and build the index
```bash
docker run --rm \
  -v $(pwd)/data:/app/data \
  pcapcat scan 
  ```
This will run 
``` python -m app.cli scan ```

# Run for example 2 : Search by protocol
```bash
docker run --rm \
  -v $(pwd)/data:/app/data \
  pcapcat search -p sip -p diameter
```
