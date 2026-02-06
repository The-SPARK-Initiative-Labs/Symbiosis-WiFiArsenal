        async function scanNetworks() {
            const duration = document.getElementById('scanDuration').value || 30;
            const output = document.getElementById('scanOutput');
            const networkList = document.getElementById('networkList');
            
            setStatus('SCANNING...', true);
            output.textContent = `Starting scan for ${duration} seconds...\n`;
            networkList.innerHTML = '';
            
            try {
                console.log('Sending scan request...');
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ duration: parseInt(duration) })
                });
                
                console.log('Got response:', response.status);
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                const result = await response.json();
                console.log('Parsed JSON:', result);
                
                output.textContent = result.output || 'Scan complete';
                
                // Display networks as clickable items
                if (result.networks && result.networks.length > 0) {
                    console.log(`Found ${result.networks.length} networks`);
                    result.networks.forEach(net => {
                        const item = document.createElement('div');
                        item.className = 'network-item';
                        item.onclick = () => selectTarget(net.bssid, net.channel, net.ssid);
                        item.innerHTML = `
                            <strong>${net.ssid || '<hidden>'}</strong><br>
                            BSSID: ${net.bssid} | Channel: ${net.channel} | Power: ${net.power} | ${net.encryption}
                        `;
                        networkList.appendChild(item);
                    });
                } else {
                    console.log('No networks found in response');
                    output.textContent += '\n\nNo networks found or error parsing results.';
                }
            } catch (error) {
                console.error('Scan error:', error);
                output.textContent = `Error: ${error.message}`;
            }
            
            setStatus('IDLE', false);
        }
