@echo off
echo Starting Clearwatch in Watch Mode...
echo.
echo This will:
echo 1. Start network monitoring
echo 2. Show real-time security alerts
echo 3. Save events to clearwatch/events/
echo 4. Log activity to clearwatch/logs/
echo.
echo Press Ctrl+C to stop monitoring
echo.
pause
python main.py --mode watch
