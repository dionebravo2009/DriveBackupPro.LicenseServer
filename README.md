# DriveBackupPro License Server

## Run locally
```bash
dotnet restore
dotnet run
```
→ Generates keys in `keys/` folder (`private.pem`, `public.pem`)

## Endpoints
- `/healthz` - server status
- `/api/public-key` - returns public key
- `/api/license` - POST JSON + header `Admin-API-Key: CHANGEME` -> returns token

Example:
```bash
curl -X POST http://localhost:5000/api/license           -H "Admin-API-Key: CHANGEME"           -H "Content-Type: application/json"           -d '{"machineId":"ABC","months":1}'
```

## Deploy to Render
Use Dockerfile and render.yaml.  
Set secrets: `Admin-API-Key` and `PRIVATE_PEM`.
