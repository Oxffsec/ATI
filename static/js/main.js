function scanQuery() {
    let query = document.getElementById('queryInput').value;
    let resultsDiv = document.getElementById('results');
    let payload = {};

    if (query.includes('.')) {
        payload['ip'] = query;
    } else {
        payload['hash'] = query;
    }

    // Show loading animation
    resultsDiv.innerHTML = "<p class='loading'>Scanning...</p>";

    fetch('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(response => response.json())
    .then(data => {
        console.log("Full API Response:", data); // Debugging
        resultsDiv.innerHTML = `<div class="output-box">
            <h3>Scan Results</h3>
            ${generateTable(data)}
        </div>`;
        
        if (data.abuseipdb && data.abuseipdb.data && data.abuseipdb.data.ipAddress) {
            fetchGeoLocation(data.abuseipdb.data.ipAddress);
        }
    })
    .catch(error => {
        resultsDiv.innerHTML = `<p style="color: red;">Error: ${error.message}</p>`;
    });
}

// Function to generate a readable table from JSON data (Handles deep nesting)
function generateTable(data, level = 0) {
    let table = '';
    
    if (level === 0) {
        table += '<table style="width:100%; border-collapse: collapse; text-align: left; border: 1px solid #ddd;">';
        table += '<tr><th>Field</th><th>Value</th></tr>';
    }

    for (let key in data) {
        if (typeof data[key] === 'object' && data[key] !== null) {
            table += `<tr><td colspan="2" style="background-color: #ff0077; color: white;"><b>${key.toUpperCase()}</b></td></tr>`;
            table += generateTable(data[key], level + 1);
        } else {
            table += `<tr><td style="border: 1px solid #ddd;">${key}</td><td style="border: 1px solid #ddd;">${data[key]}</td></tr>`;
        }
    }

    if (level === 0) {
        table += '</table>';
    }
    return table;
}

// Function to fetch accurate geolocation using ip-api.com
function fetchGeoLocation(ip) {
    fetch(`http://ip-api.com/json/${ip}`)
    .then(response => response.json())
    .then(data => {
        if (data.status === "success") {
            updateMap({
                ipAddress: ip,
                latitude: data.lat,
                longitude: data.lon,
                countryCode: data.countryCode
            });
        } else {
            console.error("Failed to fetch location data");
        }
    })
    .catch(error => console.error("Geo API Error:", error));
}

// Initialize Leaflet Map
let map = L.map('map').setView([20, 0], 2);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; OpenStreetMap contributors'
}).addTo(map);

let marker;

function updateMap(data) {
    let lat = data.latitude || 0;
    let lon = data.longitude || 0;

    if (marker) {
        map.removeLayer(marker);
    }
    marker = L.marker([lat, lon]).addTo(map)
        .bindPopup(`<b>IP:</b> ${data.ipAddress}<br><b>Country:</b> ${data.countryCode}`)
        .openPopup();
    map.setView([lat, lon], 5);
}
