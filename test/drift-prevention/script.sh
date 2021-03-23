echo 'echo "Hi, I am a new binary."' > /app/new_binary.sh
chmod +x /app/new_binary.sh
./app/new_binary.sh

echo 'echo "Hi, I am modifying the existing script."' > /app/checked_binary.sh
./app/checked_binary.sh
