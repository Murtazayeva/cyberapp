# 🛡️ CyberGuard SIEM

**CyberGuard SIEM** is a lightweight, real-time Security Information and Event Management (SIEM) dashboard. It actively monitors Nginx web server logs to detect, track, and visualize various cyber threats.

## ✨ Features

- **Real-Time Threat Detection:** Instantly identifies malicious requests from Nginx access logs.
- **GeoIP Tracking:** Resolves attacker IP addresses to display the origin country (Flag & Name).
- **Attack Categorization:** Monitors and tracks 4 major types of threats:
  - 💉 **SQL Injection (SQLi):** Captures unauthorized database queries (e.g., `UNION`, `SELECT`, `DROP`). Displays the exact payload used by the attacker.
  - 🔌 **DoS / DDoS Attacks:** Detects massive spikes in requests from single endpoints.
  - 🔑 **Credential Stuffing:** Monitors multiple failed login attempts on authentication endpoints.
  - 📂 **Data Exfiltration:** Tracks abnormally large data downloads (e.g., downloading database backups).
- **Telegram Alerts:** Sends instant notifications to an administrator's Telegram account upon detecting new threats.
- **Interactive Dashboard:** Modern, cyberpunk-styled UI built with Chart.js to visualize attack distributions.
- **Reporting & Actions:** Export threat data to CSV and instantly block malicious IP addresses.

## 🛠️ Tech Stack

- **Backend:** Python 3, Flask
- **Database:** SQLite
- **Frontend:** Vanilla JS, HTML5, CSS3, Chart.js
- **Simulations:** Custom Python Attack Simulator

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- `pip` (Python package manager)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Murtazayeva/cyberapp.git
   cd cyberapp
   ```
2. Install the required dependencies:
   ```bash
   pip install flask requests
   ```
3. *(Optional)* Configure Telegram Alerts:
   Open `app.py` and set your Telegram Bot credentials:
   ```python
   TELEGRAM_BOT_TOKEN = "your_bot_token_here"
   TELEGRAM_CHAT_ID = "your_chat_id_here"
   ```

### Running the Application
To run the SIEM dashboard locally:
```bash
python app.py
```
The dashboard will be available at `http://localhost:5000`.

### Running the Attack Simulator
To see the dashboard in action without connecting it to a real Nginx server, run the built-in attack simulator. It will generate realistic attack traffic from random global public IP addresses.
In a new terminal window, run:
```bash
python attack_simulator.py
```

## 📊 Presentation
A standalone HTML/CSS presentation is included in this repository. Simply open the `presentation.html` file in any modern web browser to view the project slides.
