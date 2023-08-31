import folium
import requests

# List of IP addresses (replace with actual IPs)
ip_list = ["8.8.8.8", "1.1.1.1", "213.55.244.58"]

# Create the map
m = folium.Map(
    location=[0, 0],
    tiles=None,
    zoom_start=2,
)

# Add a dark matter tile layer
dark_matter = folium.TileLayer(
    tiles="https://{s}.basemaps.cartocdn.com/rastertiles/dark_all/{z}/{x}/{y}.png",
    attr='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
    max_zoom=15,
    name='Dark Matter',
    control=False,
)
dark_matter.add_to(m)

# Add IP addresses as markers with custom style
for ip in ip_list:
    # Fetch location data from ipinfo.io API
    response = requests.get(f"https://ipinfo.io/{ip}/json")
    data = response.json()

    # Get latitude and longitude
    lat, lon = data["loc"].split(",")

    popup_content = f"""
        <div style="width: 200px;">
            <strong>Bot IP Address:</strong> {ip}<br>
            <strong>OS:</strong> Windows 11<br>
            <strong>Desktop Name:</strong> Malcolm
        </div>
    """

    folium.CircleMarker(
        location=[float(lat), float(lon)],
        radius=6,
        color='#FF6B6B',           
        fill=True,
        fill_color='#FF6B6B',      
        fill_opacity=0.5,           
        popup=folium.Popup(html=popup_content),
        tooltip=f"Bot IP Address: {ip}"
    ).add_to(m)

    

# Add connections between IP addresses using PolyLine with Popups
for i in range(len(ip_list) - 1):
    ip1 = ip_list[i]
    ip2 = ip_list[i + 1]

    response1 = requests.get(f"https://ipinfo.io/{ip1}/json")
    response2 = requests.get(f"https://ipinfo.io/{ip2}/json")
    
    data1 = response1.json()
    data2 = response2.json()

    lat1, lon1 = data1["loc"].split(",")
    lat2, lon2 = data2["loc"].split(",")

    folium.PolyLine(
        locations=[(float(lat1), float(lon1)), (float(lat2), float(lon2))],
        color='blue',
        weight=2,
        popup=f"Connection between IP addresses: {ip1} - {ip2}"
    ).add_to(m)

# Add Layer Control for tile layers
layer_control = folium.LayerControl(collapsed=False)
layer_control.add_to(m)

# Save the map as an HTML file
m.save('ip_map_with_custom_markers_and_connections.html')
