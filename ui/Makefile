.PHONY: run stop bank backend frontend clean

run: stop bank backend frontend

stop:
	-pkill -f "./bank -p 3000 -s bank.auth" || true
	-pkill -f "node server.js" || true
	-pkill -f "vite" || true

bank:
	cd ../build && rm -f bank.auth && ./bank -p 3000 -s bank.auth &

backend:
	cd backend && npm install && npm start &

frontend:
	cd frontend && npm install && npm run build && npm run dev

clean:
	$(MAKE) stop
	rm -rf backend/node_modules frontend/node_modules frontend/dist
