.PHONY: run bank backend frontend clean

run: bank backend frontend

bank:
	cd ../build && ./bank -p 3000 -s bank.auth &

backend:
	cd backend && npm install && npm start &

frontend:
	cd frontend && npm install && npm run build && npm run dev

clean:
	-pkill -f "../build/bank -p 3000 -s bank.auth" || true
	-pkill -f "node server.js" || true
	-pkill -f "vite" || true
	rm -rf backend/node_modules frontend/node_modules frontend/dist
