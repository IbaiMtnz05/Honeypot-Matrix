// Matrix Rain Effect
        function createMatrixRain() {
            const matrixContainer = document.getElementById('matrix-rain');
            const characters = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            
            function createChar() {
                const char = document.createElement('div');
                char.classList.add('matrix-char');
                char.textContent = characters[Math.floor(Math.random() * characters.length)];
                char.style.left = Math.random() * 100 + '%';
                char.style.animationDuration = (Math.random() * 3 + 2) + 's';
                char.style.animationDelay = Math.random() * 2 + 's';
                
                matrixContainer.appendChild(char);
                
                setTimeout(() => {
                    if (char.parentNode) {
                        char.parentNode.removeChild(char);
                    }
                }, 5000);
            }
            
            setInterval(createChar, 100);
        }

        // Parse timestamps robustly: treat bare ISO strings (YYYY-MM-DDTHH:MM:SS) as UTC.
        // Some data producers emit naive ISO strings without a timezone (they are UTC).
        // This helper returns a Date object that will display correctly in the visitor's
        // local timezone when using toLocaleString()/getHours() etc.
        function parseTimestamp(ts) {
            if (!ts) return new Date();
            // If already a number, treat as epoch millis
            if (typeof ts === 'number') return new Date(ts);
            // If string already contains a timezone (Z or +hh:mm/-hh:mm), let Date handle it
            if (/[zZ]$|[+\-]\d{2}:\d{2}$/.test(ts)) return new Date(ts);
            // If it matches a bare ISO like 2025-08-25T14:38:18 or with fractional seconds,
            // append 'Z' to force UTC parsing, then Date methods (getHours/getFullYear)
            // will reflect local timezone when used.
            if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(ts)) {
                return new Date(ts + 'Z');
            }
            // Fallback
            return new Date(ts);
        }



        // Scroll progress bar
        function initScrollProgress() {
            const progressBar = document.getElementById('scroll-progress');
            
            window.addEventListener('scroll', () => {
                const scrollTop = window.pageYOffset;
                const docHeight = document.documentElement.scrollHeight - window.innerHeight;
                const scrollPercent = (scrollTop / docHeight) * 100;
                
                progressBar.style.width = scrollPercent + '%';
            });
        }



        // Scroll progress bar
        function initScrollProgress() {
            const scrollProgress = document.getElementById('scroll-progress');
            if (!scrollProgress) return;
            
            window.addEventListener('scroll', () => {
                const scrollTop = window.pageYOffset;
                const docHeight = document.body.offsetHeight - window.innerHeight;
                const scrollPercent = (scrollTop / docHeight) * 100;
                scrollProgress.style.width = scrollPercent + '%';
            });
        }

        // Dashboard Class
        class HoneypotMatrix {
            constructor() {
                console.log('HoneypotMatrix constructor starting...');
                this.map = null;
                this.charts = {};
                this.data = {
                    summary: {},
                    attacks: [],
                    hourlyStats: {}
                };
                this.terminalLines = [];
                this.lastActivityTime = null;
                this.lastDataUpdateTime = null; // Track when we last received data
                this.statusCheckInterval = null;
                this.currentStatValues = {}; // Track current animated values to prevent unnecessary animations
                console.log('HoneypotMatrix data initialized, calling init()...');
                this.init();
            }

            checkHoneypotStatus() {
                const statusDot = document.getElementById('status-dot');
                const statusText = document.getElementById('status-text');
                
                if (!this.data.attacks || this.data.attacks.length === 0) {
                    statusDot.className = 'status-dot stopped';
                    statusText.textContent = 'No Data';
                    return;
                }

                // Get the most recent attack timestamp
                const latestAttack = this.data.attacks[this.data.attacks.length - 1];
                const latestTimestamp = parseTimestamp(latestAttack.timestamp);
                this.lastDataUpdateTime = latestTimestamp; // Store for update time display
                
                const currentTime = new Date();
                const timeDiff = (currentTime - latestTimestamp) / (1000 * 60); // minutes

                // If no activity in the last 5 minutes, mark as stopped
                if (timeDiff > 10) {
                    statusDot.className = 'status-dot stopped';
                    statusText.textContent = 'Stopped';
                } else {
                    statusDot.className = 'status-dot';
                    statusText.textContent = 'Active';
                }
            }

            startStatusChecking() {
                // Check status every 5 seconds for faster updates
                this.statusCheckInterval = setInterval(() => {
                    this.checkHoneypotStatus();
                }, 5000);
                
                // Initial check
                this.checkHoneypotStatus();
            }

            async init() {
                console.log('Init method starting...');
                try {
                    console.log('Setting timezone indicator...');
                    // Set timezone indicator
                    this.updateTimezoneIndicator();
                    
                    console.log('Starting loading delay...');
                    // Add random loading delay (1-2 seconds) for better UX
                    const loadingDelay = 1000 + Math.random() * 1000; // 1-2 seconds
                    await new Promise(resolve => setTimeout(resolve, loadingDelay));
                    
                    console.log('Loading data...');
                    await this.loadData();
                    console.log('Initializing map...');
                    this.initMap();
                    console.log('Creating charts...');
                    this.createCharts();
                    console.log('Populating table...');
                    this.populateTable();
                    console.log('Updating stats...');
                    this.updateStats();
                    console.log('Starting terminal feed...');
                    this.startTerminalFeed();
                    
                    console.log('Setting up auto-refresh...');
                    // Auto-refresh every 5 minutes
                    setInterval(() => this.loadData(), 5 * 60 * 1000);
                    console.log('Initialization completed successfully!');
                } catch (error) {
                    console.error('Dashboard initialization failed:', error);
                    this.showError('Failed to initialize dashboard: ' + error.message);
                } finally {
                    console.log('Hiding loading screen...');
                    // Always hide loading screen
                    this.hideLoading();
                }
            }

            async loadData() {
                try {
                    console.log('Loading honeypot data...');
                    
                    // Try to fetch real data from server
                    const [summaryRes, attacksRes, hourlyRes] = await Promise.all([
                        fetch('./data/summary.json').catch(() => null),
                        fetch('./data/attacks.json').catch(() => null),
                        fetch('./data/hourly_stats.json').catch(() => null)
                    ]);

                    let hasRealData = false;

                    if (summaryRes && summaryRes.ok) {
                        this.data.summary = await summaryRes.json();
                        hasRealData = true;
                    }

                    if (attacksRes && attacksRes.ok) {
                        this.data.attacks = await attacksRes.json();
                        // Set initial last data update time
                        if (this.data.attacks.length > 0) {
                            const latestAttack = this.data.attacks[this.data.attacks.length - 1];
                            this.lastDataUpdateTime = parseTimestamp(latestAttack.timestamp);
                        }
                        hasRealData = true;
                    }

                    if (hourlyRes && hourlyRes.ok) {
                        this.data.hourlyStats = await hourlyRes.json();
                        hasRealData = true;
                    }

                    if (!hasRealData) {
                        console.log('No real data found, using demo data...');
                        // Use demo data instead of throwing an error
                        this.data = {
                            summary: {
                                total_attacks: 69,
                                unique_ips: 18,
                                services_targeted: { SSH: 25, HTTP: 20, FTP: 15, TELNET: 9 },
                                countries: { Russia: 25, China: 20, USA: 15, Germany: 9 },
                                top_attackers: { "192.168.1.100": 15, "10.0.0.50": 12, "172.16.0.25": 10 }
                            },
                            attacks: [
                                {
                                    timestamp: new Date().toISOString(),
                                    src_ip: "192.168.1.100",
                                    dst_port: 22,
                                    service: "ssh",
                                    country: "Russia"
                                },
                                {
                                    timestamp: new Date(Date.now() - 60000).toISOString(),
                                    src_ip: "10.0.0.50", 
                                    dst_port: 80,
                                    service: "http",
                                    country: "China"
                                }
                            ],
                            hourlyStats: {}
                        };
                        // Set demo data update time
                        this.lastDataUpdateTime = new Date();
                    }

                    // Color countries that have attacked based on summary data
                    setTimeout(() => this.colorAttackingCountries(), 1000);

                    console.log('Data loaded successfully:', {
                        attacks: this.data.attacks.length,
                        summary: Object.keys(this.data.summary).length
                    });

                    // Update derived stats and charts after loading
                    try {
                        this.updateStats();
                        this.updateCharts();
                        this.startStatusChecking(); // Start status monitoring
                    } catch (e) { /* ignore if charts not yet ready */ }

                } catch (error) {
                    console.error('Data loading failed:', error);
                    console.log('Using fallback demo data due to loading error...');
                    // Use demo data as fallback
                    this.data = {
                        summary: {
                            total_attacks: 42,
                            unique_ips: 12,
                            services_targeted: { SSH: 20, HTTP: 15, FTP: 7 },
                            countries: { Russia: 18, China: 14, USA: 10 },
                            top_attackers: { "192.168.1.100": 8, "10.0.0.50": 7, "172.16.0.25": 6 }
                        },
                        attacks: [],
                        hourlyStats: {}
                    };
                    // Set fallback data update time
                    this.lastDataUpdateTime = new Date();
                }
            }

            colorAttackingCountries() {
                if (!this._worldSvg || !this.data.summary?.countries) {
                    console.log('Cannot color countries - missing world SVG or country data');
                    return;
                }

                console.log('Coloring countries that have attacked:', Object.keys(this.data.summary.countries));

                // Color all countries that appear in the summary data
                Object.keys(this.data.summary.countries).forEach(countryName => {
                    const attackCount = this.data.summary.countries[countryName];
                    if (attackCount > 0) {
                        this.setCountryAsAttacked(countryName);
                    }
                });
            }

            setCountryAsAttacked(countryName) {
                if (!this._worldSvg || !countryName) return;
                
                // Use the same country mapping as before
                const countryMappings = {
                    'United States': ['US', 'USA', 'United States of America'],
                    'Russia': ['RU', 'Russian Federation'],
                    'China': ['CN', 'People\'s Republic of China'],
                    'United Kingdom': ['GB', 'UK', 'England', 'Britain'],
                    'Germany': ['DE', 'Deutschland'],
                    'France': ['FR', 'Francia', 'French', 'Corsica', 'Corse'],
                    'Brazil': ['BR', 'Brasil'],
                    'India': ['IN', 'Bharat'],
                    'Japan': ['JP', 'Nippon'],
                    'Canada': ['CA'],
                    'Australia': ['AU'],
                    'South Korea': ['KR', 'Korea'],
                    'Netherlands': ['NL', 'Holland'],
                    'The Netherlands': ['NL', 'Holland', 'Netherlands'],
                    'Spain': ['ES', 'España'],
                    'Italy': ['IT', 'Italia'],
                    'Poland': ['PL', 'Polska'],
                    'Turkey': ['TR', 'Türkiye'],
                    'Türkiye': ['TR', 'Turkey'],
                    'Ukraine': ['UA'],
                    'Vietnam': ['VN', 'Viet Nam'],
                    'Thailand': ['TH'],
                    'Indonesia': ['ID'],
                    'Mexico': ['MX', 'México'],
                    'Argentina': ['AR'],
                    'South Africa': ['ZA'],
                    'Egypt': ['EG'],
                    'Iran': ['IR'],
                    'Israel': ['IL'],
                    'Saudi Arabia': ['SA'],
                    'Pakistan': ['PK'],
                    'Bangladesh': ['BD'],
                    'Nigeria': ['NG'],
                    'Kenya': ['KE'],
                    'Morocco': ['MA'],
                    'Algeria': ['DZ'],
                    'Sweden': ['SE', 'Sverige'],
                    'Norway': ['NO', 'Norge'],
                    'Finland': ['FI', 'Suomi'],
                    'Denmark': ['DK', 'Danmark'],
                    'Belgium': ['BE', 'België'],
                    'Switzerland': ['CH', 'Schweiz'],
                    'Austria': ['AT', 'Österreich'],
                    'Czech Republic': ['CZ', 'Czechia'],
                    'Romania': ['RO', 'România'],
                    'Bulgaria': ['BG', 'България'],
                    'Greece': ['GR', 'Hellas'],
                    'Portugal': ['PT'],
                    'Ireland': ['IE', 'Éire'],
                    'Hungary': ['HU', 'Magyarország'],
                    'Slovakia': ['SK', 'Slovensko'],
                    'Slovenia': ['SI', 'Slovenija'],
                    'Croatia': ['HR', 'Hrvatska'],
                    'Serbia': ['RS', 'Srbija'],
                    'Bosnia and Herzegovina': ['BA'],
                    'Montenegro': ['ME', 'Crna Gora'],
                    'North Macedonia': ['MK', 'Macedonia'],
                    'Albania': ['AL', 'Shqipëria'],
                    'Latvia': ['LV', 'Latvija'],
                    'Lithuania': ['LT', 'Lietuva'],
                    'Estonia': ['EE', 'Eesti'],
                    'Belarus': ['BY', 'Беларусь'],
                    'Moldova': ['MD'],
                    'Georgia': ['GE', 'საქართველო'],
                    'Armenia': ['AM', 'Հայաստան'],
                    'Azerbaijan': ['AZ', 'Azərbaycan'],
                    'Kazakhstan': ['KZ', 'Қазақстан'],
                    'Uzbekistan': ['UZ', 'Oʻzbekiston'],
                    'Kyrgyzstan': ['KG', 'Кыргызстан'],
                    'Tajikistan': ['TJ', 'Тоҷикистон'],
                    'Turkmenistan': ['TM', 'Türkmenistan'],
                    'Afghanistan': ['AF', 'افغانستان'],
                    'Mongolia': ['MN', 'Монгол'],
                    'North Korea': ['KP', 'DPRK'],
                    'Myanmar': ['MM', 'Burma'],
                    'Laos': ['LA'],
                    'Cambodia': ['KH', 'Kampuchea'],
                    'Malaysia': ['MY'],
                    'Singapore': ['SG'],
                    'Philippines': ['PH', 'Pilipinas'],
                    'Taiwan': ['TW', 'Formosa'],
                    'Hong Kong': ['HK'],
                    'Macau': ['MO'],
                    'Sri Lanka': ['LK', 'Ceylon'],
                    'Nepal': ['NP', 'नेपाल'],
                    'Bhutan': ['BT', 'འབྲུག་ཡུལ་'],
                    'Maldives': ['MV'],
                    'Chile': ['CL'],
                    'Peru': ['PE', 'Perú'],
                    'Ecuador': ['EC'],
                    'Colombia': ['CO'],
                    'Venezuela': ['VE'],
                    'Guyana': ['GY'],
                    'Suriname': ['SR'],
                    'Uruguay': ['UY'],
                    'Paraguay': ['PY'],
                    'Bolivia': ['BO'],
                    'Cuba': ['CU'],
                    'Jamaica': ['JM'],
                    'Haiti': ['HT', 'Haïti'],
                    'Dominican Republic': ['DO'],
                    'Costa Rica': ['CR'],
                    'Panama': ['PA', 'Panamá'],
                    'Guatemala': ['GT'],
                    'Belize': ['BZ'],
                    'Honduras': ['HN'],
                    'El Salvador': ['SV'],
                    'Nicaragua': ['NI'],
                    'Seychelles': ['SC'],
                    'Mauritius': ['MU'],
                    'Tunisia': ['TN'],
                    'Monaco': ['MC']
                };
                
                // Get possible name variations
                const possibleNames = [countryName];
                if (countryMappings[countryName]) {
                    possibleNames.push(...countryMappings[countryName]);
                }
                
                // Try to find the country path
                let countryPath = null;
                let allPaths = [];
                
                for (const name of possibleNames) {
                    const selectors = [
                        `path[id*="${name}"]`,
                        `path[class*="${name}"]`,
                        `path[data-name="${name}"]`,
                        `path[data-country="${name}"]`,
                        `path[title="${name}"]`,
                        `path[name="${name}"]`,
                        `g[id*="${name}"] path`,
                        `g[class*="${name}"] path`
                    ];
                    
                    for (const selector of selectors) {
                        const paths = this._worldSvg.querySelectorAll(selector);
                        allPaths.push(...paths);
                    }
                }
                
                // Mark all found paths (to handle territories)
                if (allPaths.length > 0) {
                    allPaths.forEach(path => {
                        path.classList.add('has-attacked');
                    });
                    console.log(`Marked ${allPaths.length} path(s) as attacked for:`, countryName);
                } else {
                    console.log('Country path not found for:', countryName);
                }
            }

            initMap() {
                // Initialize the interactive SVG world map with animated attack arcs
                this.mapElements = {
                    container: document.getElementById('attack-map'),
                    viewport: document.getElementById('map-viewport'),
                    inner: document.getElementById('map-inner'),
                    overlay: document.getElementById('attack-map-overlay'),
                    legend: document.getElementById('map-legend')
                };
                if (!this.mapElements.container) return;
                this._mapLoaded = false;
                this._mapScale = 1;
                this._targetScale = 1;
                this._mapTranslate = { x: 0, y: 0 };
                this._targetTranslate = { x: 0, y: 0 };
                this._panVelocity = { x:0, y:0 };
                this._honeypotLat = 40.4168; // Madrid, Spain
                this._honeypotLon = -3.7038;
                this._serviceColors = {};
                this._drawnAttackKeys = new Set();
                this._attackPaths = [];
                this._geoCache = {};
                this._countryCapitals = {
                    'Russia':'Moscow', 'China':'Beijing', 'USA':'Washington DC', 'United States':'Washington DC', 'Germany':'Berlin', 'France':'Paris', 'United Kingdom':'London', 'UK':'London', 'Brazil':'Brasília', 'India':'New Delhi', 'Japan':'Tokyo', 'Canada':'Ottawa', 'Australia':'Canberra', 'Netherlands':'Amsterdam', 'Italy':'Rome', 'Spain':'Madrid', 'Mexico':'Mexico City', 'Turkey':'Ankara', 'South Korea':'Seoul', 'Korea, Republic of':'Seoul', 'Iran':'Tehran', 'Vietnam':'Hanoi', 'Indonesia':'Jakarta', 'Thailand':'Bangkok', 'Poland':'Warsaw', 'Ukraine':'Kiev', 'Romania':'Bucharest', 'Czech Republic':'Prague', 'Hungary':'Budapest', 'Argentina':'Buenos Aires', 'Colombia':'Bogotá', 'Chile':'Santiago', 'Peru':'Lima', 'Venezuela':'Caracas', 'South Africa':'Cape Town', 'Egypt':'Cairo', 'Morocco':'Rabat', 'Nigeria':'Abuja', 'Kenya':'Nairobi', 'Israel':'Jerusalem', 'Saudi Arabia':'Riyadh', 'UAE':'Abu Dhabi', 'Singapore':'Singapore', 'Malaysia':'Kuala Lumpur', 'Philippines':'Manila', 'Bangladesh':'Dhaka', 'Pakistan':'Islamabad', 'Afghanistan':'Kabul', 'Iraq':'Baghdad', 'Syria':'Damascus', 'Lebanon':'Beirut', 'Jordan':'Amman', 'Kuwait':'Kuwait City', 'Qatar':'Doha', 'Bahrain':'Manama', 'Oman':'Muscat', 'Yemen':'Sanaa'
                };
                this.loadWorldMap();
                this.attachMapControls();
            }

            attachMapControls() {
                const { container, inner } = this.mapElements;
                if (!container) return;
                container.querySelectorAll('.map-btn[data-zoom]').forEach(btn=>{
                    btn.addEventListener('click', ()=>{
                        const dir = btn.dataset.zoom === 'in' ? 1 : -1; 
                        const center = { x: inner.clientWidth/2, y: inner.clientHeight/2 };
                        this.zoomMap(dir, center);
                    });
                });
                const resetBtn = container.querySelector('.map-btn[data-reset]');
                if (resetBtn) resetBtn.addEventListener('click', ()=>{ 
                    this._targetScale=1; this._mapScale=1; 
                    this._mapTranslate={x:0,y:0}; this._targetTranslate={x:0,y:0}; 
                    this.applyMapTransform(true); 
                });
                // Wheel zoom - only when hovering over the map SVG itself
                const mapSvgContainer = this.mapElements.inner;
                mapSvgContainer.addEventListener('wheel', (e)=>{
                    // Check if mouse is actually over the SVG map, not just the container
                    const svg = mapSvgContainer.querySelector('svg.world-map');
                    if (!svg) return;
                    
                    const svgRect = svg.getBoundingClientRect();
                    const mouseX = e.clientX;
                    const mouseY = e.clientY;
                    
                    // Only zoom if mouse is within the actual SVG bounds
                    if (mouseX >= svgRect.left && mouseX <= svgRect.right && 
                        mouseY >= svgRect.top && mouseY <= svgRect.bottom) {
                        e.preventDefault();
                        const rect = this.mapElements.viewport.getBoundingClientRect();
                        const point = { x: e.clientX - rect.left, y: e.clientY - rect.top };
                        this.zoomMap(e.deltaY < 0 ? 1 : -1, point);
                    }
                }, { passive:false });
                // Drag to pan with reduced friction
                let isDown=false, start={x:0,y:0}, origin={x:0,y:0}, lastMoveTime=0, lastPos={x:0,y:0};
                inner.addEventListener('pointerdown', e=>{ 
                    isDown=true; inner.classList.add('grabbing'); 
                    start={x:e.clientX,y:e.clientY}; origin={...this._mapTranslate}; 
                    lastPos={x:e.clientX,y:e.clientY}; this._panVelocity={x:0,y:0}; 
                });
                window.addEventListener('pointerup', e=>{ 
                    if(!isDown) return; isDown=false; inner.classList.remove('grabbing'); 
                    const dt = performance.now()-lastMoveTime; 
                    if (dt < 50) { this._panVelocity.x *= 0.3; this._panVelocity.y *= 0.3; } 
                });
                window.addEventListener('pointermove', e=>{ 
                    if(!isDown) return; 
                    const dx = e.clientX - start.x; const dy = e.clientY - start.y; 
                    const newTranslate = { x: origin.x + dx, y: origin.y + dy };
                    const constrainedTranslate = this.constrainTranslation(newTranslate, this._mapScale);
                    this._targetTranslate.x = constrainedTranslate.x; 
                    this._targetTranslate.y = constrainedTranslate.y; 
                    this._panVelocity.x = (e.clientX - lastPos.x) * 0.5; this._panVelocity.y = (e.clientY - lastPos.y) * 0.5; 
                    lastPos={x:e.clientX,y:e.clientY}; lastMoveTime=performance.now(); 
                });
                this.startMapSmoothingLoop();
            }

            constrainTranslation(translate, scale) {
                if (!this.mapElements?.viewport || !this.mapElements?.inner) return translate;
                
                const viewportRect = this.mapElements.viewport.getBoundingClientRect();
                
                // Get actual SVG dimensions
                const svg = this.mapElements.inner.querySelector('svg.world-map');
                if (!svg) return translate;
                
                const svgRect = svg.getBoundingClientRect();
                const baseWidth = svgRect.width / this._mapScale; // Get unscaled width
                const baseHeight = svgRect.height / this._mapScale; // Get unscaled height
                
                // Calculate map dimensions when scaled
                const mapWidth = baseWidth * scale;
                const mapHeight = baseHeight * scale;
                
                // Add extra margin for dragging (30% vertical, 15% horizontal)
                const verticalMargin = viewportRect.height * 0.15;
                const horizontalMargin = viewportRect.width * 0.15;
                
                // Calculate bounds to keep map edges within viewport
                // If map is smaller than viewport, center it
                // If map is larger than viewport, constrain edges with margin
                let minX, maxX, minY, maxY;
                
                if (mapWidth <= viewportRect.width) {
                    // Center horizontally if map is smaller than viewport
                    const centerX = (viewportRect.width - mapWidth) / 2;
                    minX = maxX = centerX;
                } else {
                    // Constrain edges with margin for horizontal dragging
                    minX = viewportRect.width - mapWidth - horizontalMargin;
                    maxX = horizontalMargin;
                }
                
                if (mapHeight <= viewportRect.height) {
                    // Center vertically if map is smaller than viewport
                    const centerY = (viewportRect.height - mapHeight) / 2;
                    minY = maxY = centerY;
                } else {
                    // Constrain edges with extra margin for vertical dragging
                    minY = viewportRect.height - mapHeight - verticalMargin;
                    maxY = verticalMargin;
                }
                
                return {
                    x: Math.max(minX, Math.min(maxX, translate.x)),
                    y: Math.max(minY, Math.min(maxY, translate.y))
                };
            }

            zoomMap(direction, center) {
                const factor = direction > 0 ? 1.3 : 0.77;  // Better zoom steps
                const newTarget = Math.min(6, Math.max(0.8, this._targetScale * factor)); // Limit zoom out to 0.8x (one level below reset)
                
                if (center && this.mapElements?.viewport) {
                    // Get viewport center if no specific center provided
                    const rect = this.mapElements.viewport.getBoundingClientRect();
                    const viewportCenter = center || {
                        x: rect.width / 2,
                        y: rect.height / 2
                    };
                    
                    // Convert viewport point to map coordinates
                    const mapPoint = {
                        x: (viewportCenter.x - this._mapTranslate.x) / this._mapScale,
                        y: (viewportCenter.y - this._mapTranslate.y) / this._mapScale
                    };
                    
                    // Calculate new translation to keep the point centered
                    const newTranslate = {
                        x: viewportCenter.x - mapPoint.x * newTarget,
                        y: viewportCenter.y - mapPoint.y * newTarget
                    };
                    
                    // Apply constraints
                    const constrainedTranslate = this.constrainTranslation(newTranslate, newTarget);
                    this._targetTranslate.x = constrainedTranslate.x;
                    this._targetTranslate.y = constrainedTranslate.y;
                }
                this._targetScale = newTarget;
            }

            applyMapTransform(force=false) {
                if (!this.mapElements?.inner) return;
                if (force) {
                    this.mapElements.inner.style.transform = `translate(${this._mapTranslate.x}px, ${this._mapTranslate.y}px) scale(${this._mapScale})`;
                    return;
                }
                // Smoothly interpolate toward target
                this._mapScale += (this._targetScale - this._mapScale) * 0.15;
                this._mapTranslate.x += (this._targetTranslate.x - this._mapTranslate.x) * 0.15;
                this._mapTranslate.y += (this._targetTranslate.y - this._mapTranslate.y) * 0.15;
                this.mapElements.inner.style.transform = `translate(${this._mapTranslate.x}px, ${this._mapTranslate.y}px) scale(${this._mapScale})`;
            }

            startMapSmoothingLoop() {
                if (this._smoothingLoop) return;
                const step = ()=>{
                    // Reduced inertia for less ice-like feel
                    if (Math.abs(this._panVelocity.x) > 0.2 || Math.abs(this._panVelocity.y) > 0.2) {
                        const newTranslate = {
                            x: this._targetTranslate.x + this._panVelocity.x * 0.6,
                            y: this._targetTranslate.y + this._panVelocity.y * 0.6
                        };
                        const constrainedTranslate = this.constrainTranslation(newTranslate, this._targetScale);
                        this._targetTranslate.x = constrainedTranslate.x;
                        this._targetTranslate.y = constrainedTranslate.y;
                        this._panVelocity.x *= 0.85;
                        this._panVelocity.y *= 0.85;
                    }
                    this.applyMapTransform();
                    this._smoothingLoop = requestAnimationFrame(step);
                };
                this._smoothingLoop = requestAnimationFrame(step);
            }

            async loadWorldMap() {
                if (this._mapLoaded) return;
                const { inner, overlay, status } = this.mapElements;
                try {
                    let res = await fetch('./world.svg').catch(()=>null);
                    if (!res || !res.ok) res = await fetch('world.svg').catch(()=>null);
                    if (!res.ok) throw new Error('SVG not found');
                    const svgText = await res.text();
                    // Insert world map
                    const temp = document.createElement('div');
                    temp.innerHTML = svgText.trim();
                    const worldSvg = temp.querySelector('svg');
                    if (!worldSvg) throw new Error('Invalid SVG');
                    worldSvg.classList.add('world-map');
                    // Ensure viewBox exists
                    let vb = worldSvg.getAttribute('viewBox');
                    if (!vb) {
                        const w = parseFloat(worldSvg.getAttribute('width'))||2000;
                        const h = parseFloat(worldSvg.getAttribute('height'))||1000;
                        worldSvg.setAttribute('viewBox', `0 0 ${w} ${h}`);
                        vb = worldSvg.getAttribute('viewBox');
                    }
                    const [minx,miny,wv,hv] = worldSvg.getAttribute('viewBox').split(/\s+/).map(Number);
                    this._mapWidth = wv; this._mapHeight = hv;
                    
                    // Store reference to world SVG for country coloring
                    this._worldSvg = worldSvg;
                    
                    // Create attack layers directly in the world SVG
                    const attackGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
                    attackGroup.id = 'attack-lines';
                    attackGroup.style.pointerEvents = 'none';
                    worldSvg.appendChild(attackGroup);
                    
                    const markerGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
                    markerGroup.id = 'attack-markers';
                    markerGroup.style.pointerEvents = 'none';
                    worldSvg.appendChild(markerGroup);
                    
                    this._linesGroup = attackGroup;
                    this._markersGroup = markerGroup;
                    
                    inner.insertBefore(worldSvg, overlay);
                    // Hide the overlay since we're not using it
                    overlay.style.display = 'none';
                    
                    // Add honeypot marker using known coordinates for Spain
                    // For a typical world map SVG with viewBox "0 0 2000 1000", Spain is roughly at:
                    // Movement options (2 grid boxes = 80px):
                    // Left: X=870    Right: X=1030
                    // Up: Y=300      Down: Y=460
                    const spainX = 975;
                    const spainY = 226;
                    
                    const hp = document.createElementNS('http://www.w3.org/2000/svg','circle');
                    hp.setAttribute('cx', spainX); 
                    hp.setAttribute('cy', spainY); 
                    hp.setAttribute('r', 4); 
                    hp.setAttribute('class','honeypot-marker');
                    hp.setAttribute('data-label','HONEYPOT (ES)');
                    this._markersGroup.appendChild(hp);
                    
                    // Store Spain coordinates
                    this._spainX = spainX;
                    this._spainY = spainY;
                    this._mapLoaded = true;
                    
                    // Initialize all service colors immediately for legend display
                    this.initializeAllServiceColors();
                    
                    // Do NOT draw historical attacks; only new live ones
                } catch (e) {
                    console.error('Map load failed', e);
                }
            }

            latLonToXY(lat, lon) {
                // Use viewBox dimensions for consistent positioning regardless of screen size
                const w = this._mapWidth || 2000; 
                const h = this._mapHeight || 1000;
                
                // Use viewBox coordinates directly for consistent positioning
                const x = (lon + 180) / 360 * w;
                const y = (90 - lat) / 180 * h;
                
                return [x, y];
            }

            resolveGeo(attack) {
                const key = (attack.city||'') + '|' + (attack.country||'');
                if (this._geoCache[key]) return this._geoCache[key];
                let latLon = null;
                
                // Try city first, then country capital, then skip
                if (attack.city && this._cityCoords[attack.city]) {
                    latLon = this._cityCoords[attack.city];
                } else if (attack.country) {
                    const capital = this._countryCapitals[attack.country];
                    if (capital && this._cityCoords[capital]) {
                        latLon = this._cityCoords[capital];
                    } else if (this._countryCoords[attack.country]) {
                        latLon = this._countryCoords[attack.country];
                    }
                }
                
                if (!latLon) {
                    // Unknown geo -> skip drawing
                    return null;
                }
                this._geoCache[key] = latLon;
                return latLon;
            }

            serviceColor(serviceRaw) {
                const service = (serviceRaw||'OTHER').toUpperCase();
                if (this._serviceColors[service]) return this._serviceColors[service];
                
                // Colors for your actual attack vectors - highly distinct and easy to differentiate
                const serviceColorMap = {
                    'SMB': '#00ff00',      // Bright green - SMB attacks (most common)
                    'TELNET': '#0080ff',   // Pure blue - Telnet attacks  
                    'HTTP': '#ff8000',     // Orange - HTTP attacks
                    'EPMAP': '#ffff00',    // Bright yellow - EPMAP attacks
                    'MSSQL': '#ff0080',    // Magenta - MSSQL attacks
                    'MYSQL': '#00ffff',    // Cyan - MySQL attacks
                    'MEMCACHE': '#8000ff', // Purple - Memcache attacks
                    'MONGO': '#80ff00',    // Lime green - MongoDB attacks
                    'SIP': '#ff4000',      // Red-orange - SIP attacks
                    'FTP': '#0040ff',      // Deep blue - FTP attacks
                    'OTHER': '#c0c0c0'     // Light gray - Other/Unknown attacks
                };
                
                // Use predefined color if available, otherwise generate one for unknown services
                if (serviceColorMap[service]) {
                    this._serviceColors[service] = serviceColorMap[service];
                } else {
                    // Generate distinct colors for any unexpected services
                    const fallbackPalette = [
                        '#ff6600', '#00cc66', '#6600ff', '#cc6600',
                        '#0066cc', '#cc0066', '#66cc00', '#ff66ff'
                    ];
                    const unknownServices = Object.keys(this._serviceColors).filter(s => !serviceColorMap[s]);
                    const idx = unknownServices.length % fallbackPalette.length;
                    this._serviceColors[service] = fallbackPalette[idx];
                }
                
                this.refreshLegend();
                return this._serviceColors[service];
            }

            initializeAllServiceColors() {
                // Pre-populate colors for your actual attack vectors
                const yourServices = [
                    'SMB', 'TELNET', 'HTTP', 'EPMAP', 'MSSQL', 
                    'MYSQL', 'MEMCACHE', 'MONGO', 'SIP', 'FTP'
                ];
                
                yourServices.forEach(service => {
                    this.serviceColor(service); // This will populate the color and update legend
                });
            }

            refreshLegend() {
                const { legend } = this.mapElements; 
                if (!legend) return;
                
                // Sort services by name for consistent display
                const sortedServices = Object.entries(this._serviceColors).sort((a, b) => a[0].localeCompare(b[0]));
                
                legend.innerHTML = `
                    <div style="margin-bottom: 8px; font-weight: bold; color: #00ff41; font-size: 0.9em;">
                        <i class="fas fa-palette"></i> Attack Types & Colors
                    </div>
                    ${sortedServices.map(([svc, color]) => `
                        <div class="legend-item" title="${svc} attacks">
                            <span class="legend-color" style="background: ${color}; color: ${color}"></span>
                            <span>${svc}</span>
                        </div>
                    `).join('')}
                `;
            }

            addMapAttack(attack) {
                if (!this._mapLoaded || !attack) return;
                
                console.log('Processing attack from:', attack.src_ip, attack.country, 'service:', attack.service);
                
                const key = `${attack.timestamp||''}|${attack.src_ip}`;
                if (this._drawnAttackKeys.has(key)) return;
                this._drawnAttackKeys.add(key);
                
                // Get attack color based on service  
                const color = this.serviceColor(attack.service);
                
                // Light up the attacking country temporarily with service color
                if (attack.country) {
                    this.lightUpCountry(attack.country, color);
                }
                
                console.log('Country', attack.country, 'lit up with color:', color);
                
                // Auto-reset after 5 seconds
                setTimeout(() => {
                    if (attack.country) {
                        this.resetCountryColor(attack.country);
                    }
                    this._drawnAttackKeys.delete(key);
                }, 5000);
            }

            addMapAttackWithAnimation(attack) {
                if (!this._mapLoaded || !attack) return;
                
                console.log('Adding animated attack from:', attack.src_ip, attack.country, 'service:', attack.service);
                
                // Get attack coordinates from the attack data itself
                const attackLat = attack.lat;
                const attackLon = attack.lon;
                
                if (!attackLat || !attackLon) {
                    console.log('No coordinates found for attack, skipping animation');
                    // Fall back to basic country highlighting
                    this.addMapAttack(attack);
                    return;
                }
                
                // Convert coordinates to SVG coordinates
                const [attackX, attackY] = this.latLonToXY(attackLat, attackLon);
                
                // Always use Spain coordinates as end point
                const spainX = 975;
                const spainY = 226;
                
                // Get attack color based on service
                const color = this.serviceColor(attack.service);
                
                // Light up the attacking country with blinking red effect
                if (attack.country) {
                    this.blinkCountryRed(attack.country);
                }
                
                // Create straight line animated arrow
                this.createStraightAttackArrow(attackX, attackY, spainX, spainY, color, attack);
            }

            createStraightAttackArrow(startX, startY, endX, endY, color, attack) {
                if (!this._linesGroup) return;
                
                // Create group for this attack animation
                const attackGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
                attackGroup.classList.add('attack-animation');
                
                // Create straight line path
                const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                line.setAttribute('x1', startX);
                line.setAttribute('y1', startY);
                line.setAttribute('x2', endX);
                line.setAttribute('y2', endY);
                line.setAttribute('stroke', color);
                line.setAttribute('stroke-width', '2');
                line.setAttribute('opacity', '0.8');
                line.setAttribute('stroke-dasharray', '5,3'); // Clean dashed line
                
                // Create animated dot that travels along the line
                const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                dot.setAttribute('r', '4');
                dot.setAttribute('fill', color);
                dot.setAttribute('stroke', '#ffffff');
                dot.setAttribute('stroke-width', '1');
                
                // Calculate angle for arrow head
                const angle = Math.atan2(endY - startY, endX - startX);
                const arrowSize = 6;
                
                // Create simple triangle arrow at destination
                const arrow = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
                const x1 = endX - arrowSize * Math.cos(angle - Math.PI / 6);
                const y1 = endY - arrowSize * Math.sin(angle - Math.PI / 6);
                const x2 = endX - arrowSize * Math.cos(angle + Math.PI / 6);
                const y2 = endY - arrowSize * Math.sin(angle + Math.PI / 6);
                arrow.setAttribute('points', `${endX},${endY} ${x1},${y1} ${x2},${y2}`);
                arrow.setAttribute('fill', color);
                arrow.setAttribute('stroke', '#ffffff');
                arrow.setAttribute('stroke-width', '1');
                arrow.style.opacity = '0';
                
                // Add elements to group
                attackGroup.appendChild(line);
                attackGroup.appendChild(dot);
                attackGroup.appendChild(arrow);
                
                // Add group to map
                this._linesGroup.appendChild(attackGroup);
                
                // Animate the attack
                this.animateStraightAttack(line, dot, arrow, startX, startY, endX, endY, color, attack);
                
                // Remove after animation completes
                setTimeout(() => {
                    if (attackGroup.parentNode) {
                        attackGroup.parentNode.removeChild(attackGroup);
                    }
                }, 4000);
            }

            animateStraightAttack(line, dot, arrow, startX, startY, endX, endY, color, attack) {
                const distance = Math.sqrt((endX - startX) ** 2 + (endY - startY) ** 2);
                const duration = 2000; // 2 seconds for clean animation
                const startTime = performance.now();
                
                // Set up line dash animation
                line.style.strokeDasharray = `${distance}`;
                line.style.strokeDashoffset = distance;
                
                const animate = (currentTime) => {
                    const elapsed = currentTime - startTime;
                    const progress = Math.min(elapsed / duration, 1);
                    
                    // Linear progress for cleaner feel
                    const easeProgress = progress;
                    
                    // Draw line progressively
                    const lineProgress = Math.min(elapsed / (duration * 0.6), 1); // Line draws in first 60%
                    line.style.strokeDashoffset = distance * (1 - lineProgress);
                    
                    // Move dot along line
                    const currentX = startX + (endX - startX) * easeProgress;
                    const currentY = startY + (endY - startY) * easeProgress;
                    dot.setAttribute('cx', currentX);
                    dot.setAttribute('cy', currentY);
                    
                    // Show arrow when dot is 70% complete
                    if (progress > 0.7) {
                        const arrowOpacity = (progress - 0.7) / 0.3;
                        arrow.style.opacity = arrowOpacity * 0.9;
                    }
                    
                    if (progress < 1) {
                        requestAnimationFrame(animate);
                    } else {
                        // Animation complete - add simple impact effect
                        this.addSimpleImpactEffect(endX, endY, color);
                        
                        // Mark the attacking country as permanently attacked (pink color)
                        if (attack && attack.country) {
                            console.log(`Marking ${attack.country} as permanently attacked after animation`);
                            this.setCountryAsAttacked(attack.country);
                        }
                        
                        // Keep visible briefly before fading
                        setTimeout(() => {
                            this.fadeOutStraightAttack(line, dot, arrow);
                        }, 300);
                    }
                };
                
                requestAnimationFrame(animate);
            }

            fadeOutStraightAttack(line, dot, arrow) {
                const fadeStart = performance.now();
                const fadeDuration = 800;
                
                const fade = (currentTime) => {
                    const elapsed = currentTime - fadeStart;
                    const progress = Math.min(elapsed / fadeDuration, 1);
                    const opacity = 1 - progress;
                    
                    line.style.opacity = opacity * 0.8;
                    dot.style.opacity = opacity;
                    arrow.style.opacity = opacity * 0.9;
                    
                    if (progress < 1) {
                        requestAnimationFrame(fade);
                    }
                };
                
                requestAnimationFrame(fade);
            }

            addSimpleImpactEffect(x, y, color) {
                if (!this._markersGroup) return;
                
                // Create multiple expanding circles for better impact effect
                for (let i = 0; i < 4; i++) {
                    setTimeout(() => {
                        const impact = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                        impact.setAttribute('cx', x);
                        impact.setAttribute('cy', y);
                        impact.setAttribute('r', '3');
                        impact.setAttribute('fill', 'none');
                        impact.setAttribute('stroke', color); // Use attack type color
                        impact.setAttribute('stroke-width', '3');
                        impact.setAttribute('opacity', '0.9');
                        impact.classList.add('impact-wave');
                        
                        this._markersGroup.appendChild(impact);
                        
                        // Apply CSS animation
                        impact.style.animation = 'impactWaveExpand 1.5s ease-out forwards';
                        
                        // Remove impact element after animation
                        setTimeout(() => {
                            if (impact.parentNode) {
                                impact.parentNode.removeChild(impact);
                            }
                        }, 1500);
                        
                    }, i * 200); // Stagger waves every 200ms for continuous effect
                }
                
                // Add a bright flash at the impact point
                const flash = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                flash.setAttribute('cx', x);
                flash.setAttribute('cy', y);
                flash.setAttribute('r', '6');
                flash.setAttribute('fill', color);
                flash.setAttribute('opacity', '1');
                flash.setAttribute('stroke', '#ffffff');
                flash.setAttribute('stroke-width', '2');
                
                this._markersGroup.appendChild(flash);
                
                // Flash fade out
                const flashStart = performance.now();
                const flashDuration = 300;
                
                const flashAnimate = (currentTime) => {
                    const elapsed = currentTime - flashStart;
                    const progress = Math.min(elapsed / flashDuration, 1);
                    
                    const opacity = 1 - progress;
                    const radius = 6 + progress * 4; // Slight expansion
                    
                    flash.setAttribute('opacity', opacity);
                    flash.setAttribute('r', radius);
                    
                    if (progress < 1) {
                        requestAnimationFrame(flashAnimate);
                    } else {
                        if (flash.parentNode) {
                            flash.parentNode.removeChild(flash);
                        }
                    }
                };
                
                requestAnimationFrame(flashAnimate);
            }

            blinkCountryRed(countryName) {
                if (!this._worldSvg || !countryName) return;
                
                // Find country paths using the same mapping as before
                const countryMappings = {
                    'United States': ['US', 'USA', 'United States of America'],
                    'Russia': ['RU', 'Russian Federation'],
                    'China': ['CN', 'People\'s Republic of China'],
                    'United Kingdom': ['GB', 'UK', 'England', 'Britain'],
                    'Germany': ['DE', 'Deutschland'],
                    'France': ['FR', 'Francia', 'French', 'Corsica', 'Corse'],
                    'Brazil': ['BR', 'Brasil'],
                    'India': ['IN', 'Bharat'],
                    'Japan': ['JP', 'Nippon'],
                    'Canada': ['CA'],
                    'Australia': ['AU'],
                    'South Korea': ['KR', 'Korea'],
                    'Netherlands': ['NL', 'Holland'],
                    'Spain': ['ES', 'España'],
                    'Italy': ['IT', 'Italia'],
                    'Poland': ['PL', 'Polska'],
                    'Turkey': ['TR', 'Türkiye'],
                    'Ukraine': ['UA'],
                    'Vietnam': ['VN', 'Viet Nam'],
                    'Thailand': ['TH'],
                    'Indonesia': ['ID'],
                    'Mexico': ['MX', 'México'],
                    'Argentina': ['AR'],
                    'South Africa': ['ZA'],
                    'Egypt': ['EG'],
                    'Iran': ['IR'],
                    'Israel': ['IL'],
                    'Saudi Arabia': ['SA'],
                    'Pakistan': ['PK'],
                    'Bangladesh': ['BD'],
                    'Nigeria': ['NG'],
                    'Kenya': ['KE'],
                    'Morocco': ['MA'],
                    'Algeria': ['DZ'],
                    'Sweden': ['SE', 'Sverige'],
                    'Norway': ['NO', 'Norge'],
                    'Finland': ['FI', 'Suomi'],
                    'Denmark': ['DK', 'Danmark'],
                    'Belgium': ['BE', 'België'],
                    'Switzerland': ['CH', 'Schweiz'],
                    'Austria': ['AT', 'Österreich'],
                    'Czech Republic': ['CZ', 'Czechia'],
                    'Romania': ['RO', 'România'],
                    'Bulgaria': ['BG', 'България'],
                    'Greece': ['GR', 'Hellas'],
                    'Portugal': ['PT'],
                    'Ireland': ['IE', 'Éire'],
                    'Hungary': ['HU', 'Magyarország'],
                    'Slovakia': ['SK', 'Slovensko'],
                    'Slovenia': ['SI', 'Slovenija'],
                    'Croatia': ['HR', 'Hrvatska'],
                    'Serbia': ['RS', 'Srbija'],
                    'Bosnia and Herzegovina': ['BA'],
                    'Montenegro': ['ME', 'Crna Gora'],
                    'North Macedonia': ['MK', 'Macedonia'],
                    'Albania': ['AL', 'Shqipëria'],
                    'Latvia': ['LV', 'Latvija'],
                    'Lithuania': ['LT', 'Lietuva'],
                    'Estonia': ['EE', 'Eesti'],
                    'Belarus': ['BY', 'Беларусь'],
                    'Moldova': ['MD'],
                    'Georgia': ['GE', 'საქართველო'],
                    'Armenia': ['AM', 'Հայաստան'],
                    'Azerbaijan': ['AZ', 'Azərbaycan'],
                    'Kazakhstan': ['KZ', 'Қазақстан'],
                    'Uzbekistan': ['UZ', 'Oʻzbekiston'],
                    'Kyrgyzstan': ['KG', 'Кыргызстан'],
                    'Tajikistan': ['TJ', 'Тоҷикистон'],
                    'Turkmenistan': ['TM', 'Türkmenistan'],
                    'Afghanistan': ['AF', 'افغانستان'],
                    'Mongolia': ['MN', 'Монгол'],
                    'North Korea': ['KP', 'DPRK'],
                    'Myanmar': ['MM', 'Burma'],
                    'Laos': ['LA'],
                    'Cambodia': ['KH', 'Kampuchea'],
                    'Malaysia': ['MY'],
                    'Singapore': ['SG'],
                    'Philippines': ['PH', 'Pilipinas'],
                    'Taiwan': ['TW', 'Formosa'],
                    'Hong Kong': ['HK'],
                    'Macau': ['MO'],
                    'Sri Lanka': ['LK', 'Ceylon'],
                    'Nepal': ['NP', 'नेपाल'],
                    'Bhutan': ['BT', 'འབྲུག་ཡུལ་'],
                    'Maldives': ['MV'],
                    'Chile': ['CL'],
                    'Peru': ['PE', 'Perú'],
                    'Ecuador': ['EC'],
                    'Colombia': ['CO'],
                    'Venezuela': ['VE'],
                    'Guyana': ['GY'],
                    'Suriname': ['SR'],
                    'Uruguay': ['UY'],
                    'Paraguay': ['PY'],
                    'Bolivia': ['BO'],
                    'Cuba': ['CU'],
                    'Jamaica': ['JM'],
                    'Haiti': ['HT', 'Haïti'],
                    'Dominican Republic': ['DO'],
                    'Costa Rica': ['CR'],
                    'Panama': ['PA', 'Panamá'],
                    'Guatemala': ['GT'],
                    'Belize': ['BZ'],
                    'Honduras': ['HN'],
                    'El Salvador': ['SV'],
                    'Nicaragua': ['NI']
                };
                
                // Get possible name variations
                const possibleNames = [countryName];
                if (countryMappings[countryName]) {
                    possibleNames.push(...countryMappings[countryName]);
                }
                
                // Find and animate all matching paths
                let foundPaths = [];
                for (const name of possibleNames) {
                    const selectors = [
                        `path[id*="${name}"]`,
                        `path[class*="${name}"]`,
                        `path[data-name="${name}"]`,
                        `path[data-country="${name}"]`,
                        `path[title="${name}"]`,
                        `path[name="${name}"]`,
                        `g[id*="${name}"] path`,
                        `g[class*="${name}"] path`
                    ];
                    
                    for (const selector of selectors) {
                        const paths = this._worldSvg.querySelectorAll(selector);
                        foundPaths.push(...paths);
                    }
                }
                
                if (foundPaths.length > 0) {
                    console.log(`Found ${foundPaths.length} path(s) for country: ${countryName}`);
                    
                    foundPaths.forEach((path, index) => {
                        // Store original style
                        const originalFill = path.style.fill || path.getAttribute('fill') || '';
                        const originalFilter = path.style.filter || '';
                        const originalTransform = path.style.transform || '';
                        
                        // Add attacking class for CSS animations
                        path.classList.add('attacking');
                        
                        // Set transform origin for proper scaling
                        path.style.transformOrigin = 'center';
                        
                        // Add expansive wave effect around the country
                        this.createCountryWaveEffect(path, '#ff4757', index * 200);
                        
                        console.log(`Country ${countryName} path ${index + 1} is now blinking red and scaling for 5 seconds`);
                        
                        // Reset after exactly 5 seconds
                        setTimeout(() => {
                            path.classList.remove('attacking');
                            path.style.fill = originalFill;
                            path.style.filter = originalFilter;
                            path.style.transform = originalTransform;
                            path.style.transformOrigin = '';
                            console.log(`Country ${countryName} path ${index + 1} attack animation ended`);
                        }, 5000);
                    });
                } else {
                    console.log('Country path not found for:', countryName, 'tried variations:', possibleNames);
                }
            }

            createCountryWaveEffect(countryPath, color, delay = 0) {
                if (!countryPath || !this._worldSvg) return;
                
                try {
                    // Get the bounding box of the country
                    const bbox = countryPath.getBBox();
                    const centerX = bbox.x + bbox.width / 2;
                    const centerY = bbox.y + bbox.height / 2;
                    
                    // Create multiple wave circles for expanding effect
                    for (let i = 0; i < 3; i++) {
                        setTimeout(() => {
                            const waveCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                            waveCircle.setAttribute('cx', centerX);
                            waveCircle.setAttribute('cy', centerY);
                            waveCircle.setAttribute('r', '5');
                            waveCircle.setAttribute('fill', 'none');
                            waveCircle.setAttribute('stroke', color);
                            waveCircle.setAttribute('stroke-width', '3');
                            waveCircle.setAttribute('opacity', '0.8');
                            waveCircle.classList.add('country-wave');
                            
                            // Add to SVG
                            this._worldSvg.appendChild(waveCircle);
                            
                            // Apply CSS animation
                            waveCircle.style.animation = 'countryWaveExpand 2s ease-out forwards';
                            
                            // Remove after animation
                            setTimeout(() => {
                                if (waveCircle.parentNode) {
                                    waveCircle.parentNode.removeChild(waveCircle);
                                }
                            }, 2000);
                            
                        }, delay + (i * 400)); // Stagger each wave by 400ms
                    }
                } catch (error) {
                    console.log('Could not create wave effect for country:', error);
                }
            }

            lightUpCountry(countryName, color) {
                if (!this._worldSvg || !countryName) return;
                
                // Common country name mappings for SVG paths
                const countryMappings = {
                    'United States': ['US', 'USA', 'United States of America'],
                    'Russia': ['RU', 'Russian Federation'],
                    'China': ['CN', 'People\'s Republic of China'],
                    'United Kingdom': ['GB', 'UK', 'England', 'Britain'],
                    'Germany': ['DE', 'Deutschland'],
                    'France': ['FR', 'Francia', 'French', 'Corsica', 'Corse'],
                    'Brazil': ['BR', 'Brasil'],
                    'India': ['IN', 'Bharat'],
                    'Japan': ['JP', 'Nippon'],
                    'Canada': ['CA'],
                    'Australia': ['AU'],
                    'South Korea': ['KR', 'Korea'],
                    'Netherlands': ['NL', 'Holland'],
                    'Spain': ['ES', 'España'],
                    'Italy': ['IT', 'Italia'],
                    'Poland': ['PL', 'Polska'],
                    'Turkey': ['TR', 'Türkiye'],
                    'Ukraine': ['UA'],
                    'Vietnam': ['VN', 'Viet Nam'],
                    'Thailand': ['TH'],
                    'Indonesia': ['ID'],
                    'Mexico': ['MX', 'México'],
                    'Argentina': ['AR'],
                    'South Africa': ['ZA'],
                    'Egypt': ['EG'],
                    'Iran': ['IR'],
                    'Israel': ['IL'],
                    'Saudi Arabia': ['SA'],
                    'Pakistan': ['PK'],
                    'Bangladesh': ['BD'],
                    'Nigeria': ['NG'],
                    'Kenya': ['KE'],
                    'Morocco': ['MA'],
                    'Algeria': ['DZ'],
                    'Sweden': ['SE', 'Sverige'],
                    'Norway': ['NO', 'Norge'],
                    'Finland': ['FI', 'Suomi'],
                    'Denmark': ['DK', 'Danmark'],
                    'Belgium': ['BE', 'België'],
                    'Switzerland': ['CH', 'Schweiz'],
                    'Austria': ['AT', 'Österreich'],
                    'Czech Republic': ['CZ', 'Czechia'],
                    'Romania': ['RO', 'România'],
                    'Bulgaria': ['BG', 'България'],
                    'Greece': ['GR', 'Hellas'],
                    'Portugal': ['PT'],
                    'Ireland': ['IE', 'Éire'],
                    'Hungary': ['HU', 'Magyarország'],
                    'Slovakia': ['SK', 'Slovensko'],
                    'Slovenia': ['SI', 'Slovenija'],
                    'Croatia': ['HR', 'Hrvatska'],
                    'Serbia': ['RS', 'Srbija'],
                    'Bosnia and Herzegovina': ['BA'],
                    'Montenegro': ['ME', 'Crna Gora'],
                    'North Macedonia': ['MK', 'Macedonia'],
                    'Albania': ['AL', 'Shqipëria'],
                    'Latvia': ['LV', 'Latvija'],
                    'Lithuania': ['LT', 'Lietuva'],
                    'Estonia': ['EE', 'Eesti'],
                    'Belarus': ['BY', 'Беларусь'],
                    'Moldova': ['MD'],
                    'Georgia': ['GE', 'საქართველო'],
                    'Armenia': ['AM', 'Հայաստան'],
                    'Azerbaijan': ['AZ', 'Azərbaycan'],
                    'Kazakhstan': ['KZ', 'Қазақстан'],
                    'Uzbekistan': ['UZ', 'Oʻzbekiston'],
                    'Kyrgyzstan': ['KG', 'Кыргызстан'],
                    'Tajikistan': ['TJ', 'Тоҷикистон'],
                    'Turkmenistan': ['TM', 'Türkmenistan'],
                    'Afghanistan': ['AF', 'افغانستان'],
                    'Mongolia': ['MN', 'Монгол'],
                    'North Korea': ['KP', 'DPRK'],
                    'Myanmar': ['MM', 'Burma'],
                    'Laos': ['LA'],
                    'Cambodia': ['KH', 'Kampuchea'],
                    'Malaysia': ['MY'],
                    'Singapore': ['SG'],
                    'Philippines': ['PH', 'Pilipinas'],
                    'Taiwan': ['TW', 'Formosa'],
                    'Hong Kong': ['HK'],
                    'Macau': ['MO'],
                    'Sri Lanka': ['LK', 'Ceylon'],
                    'Nepal': ['NP', 'नेपाल'],
                    'Bhutan': ['BT', 'འབྲུག་ཡུལ་'],
                    'Maldives': ['MV'],
                    'Chile': ['CL'],
                    'Peru': ['PE', 'Perú'],
                    'Ecuador': ['EC'],
                    'Colombia': ['CO'],
                    'Venezuela': ['VE'],
                    'Guyana': ['GY'],
                    'Suriname': ['SR'],
                    'Uruguay': ['UY'],
                    'Paraguay': ['PY'],
                    'Bolivia': ['BO'],
                    'Cuba': ['CU'],
                    'Jamaica': ['JM'],
                    'Haiti': ['HT', 'Haïti'],
                    'Dominican Republic': ['DO'],
                    'Costa Rica': ['CR'],
                    'Panama': ['PA', 'Panamá'],
                    'Guatemala': ['GT'],
                    'Belize': ['BZ'],
                    'Honduras': ['HN'],
                    'El Salvador': ['SV'],
                    'Nicaragua': ['NI']
                };
                
                // Get possible name variations
                const possibleNames = [countryName];
                if (countryMappings[countryName]) {
                    possibleNames.push(...countryMappings[countryName]);
                }
                
                // Try to find the country path by various attributes
                let countryPath = null;
                for (const name of possibleNames) {
                    // Try different common attributes used in world map SVGs
                    const selectors = [
                        `path[id*="${name}"]`,
                        `path[class*="${name}"]`,
                        `path[data-name="${name}"]`,
                        `path[data-country="${name}"]`,
                        `path[title="${name}"]`,
                        `path[name="${name}"]`,
                        `g[id*="${name}"] path`,
                        `g[class*="${name}"] path`
                    ];
                    
                    for (const selector of selectors) {
                        countryPath = this._worldSvg.querySelector(selector);
                        if (countryPath) break;
                    }
                    if (countryPath) break;
                }
                
                if (countryPath) {
                    // Apply dark red blinking effect for live attacks (no glow)
                    countryPath.style.fill = '#8b0000';
                    countryPath.classList.add('attacking');
                    console.log('Successfully lit up country:', countryName);
                } else {
                    console.log('Country path not found for:', countryName, 'tried variations:', possibleNames);
                }
            }

            resetCountryColor(countryName) {
                if (!this._worldSvg || !countryName) return;
                
                // Find the country path again and reset it
                const paths = this._worldSvg.querySelectorAll('path.attacking');
                paths.forEach(path => {
                    path.style.fill = '';
                    path.classList.remove('attacking');
                });
            }

            startMapAnimationLoop() {
                if (this._animatingMap) return; this._animatingMap=true;
                const flightDuration=2600, lineDrawDuration=700, fadeDuration=700;
                const loop=(t)=>{
                    for (const item of this._attackPaths) {
                        if (item.done) continue;
                        const {group,path,dot,arrow,start}=item;
                        if (!group.isConnected){ item.done=true; continue; }
                        if (!item.length) { try { item.length=path.getTotalLength(); path.style.strokeDasharray=item.length; path.style.strokeDashoffset=item.length; } catch(e){ item.length=200; } }
                        const elapsed=t-start;
                        const pLine=Math.min(1,elapsed/lineDrawDuration);
                        path.style.strokeDashoffset=(1-pLine)*item.length;
                        const pFlight=Math.min(1,elapsed/flightDuration);
                        const [x0,y0]=group.dataset.p0.split(',').map(Number);
                        const [x1,y1]=group.dataset.p1.split(',').map(Number);
                        const [x2,y2]=group.dataset.p2.split(',').map(Number);
                        const om=1-pFlight; const bx=om*om*x0 + 2*om*pFlight*x1 + pFlight*pFlight*x2; const by=om*om*y0 + 2*om*pFlight*y1 + pFlight*pFlight*y2;
                        dot.setAttribute('cx',bx.toFixed(2)); dot.setAttribute('cy',by.toFixed(2));
                        if (pFlight>0.9) arrow.style.opacity=((pFlight-0.9)/0.1).toFixed(2);
                        if (elapsed>flightDuration+fadeDuration){ group.remove(); item.done=true; }
                        else if (elapsed>flightDuration){ const fadeP=(elapsed-flightDuration)/fadeDuration; const op=(1-fadeP).toFixed(2); path.style.opacity=op; dot.style.opacity=op; arrow.style.opacity=op; }
                    }
                    // purge finished
                    this._attackPaths = this._attackPaths.filter(a=>!a.done);
                    requestAnimationFrame(loop);
                };
                requestAnimationFrame(loop);
            }
            

            createCharts() {
                // Chart.js configuration for dark theme
                Chart.defaults.color = '#fff';
                Chart.defaults.borderColor = 'rgba(0, 255, 65, 0.2)';

                // Create chart instances once (they will be updated live)
                this.createCountryChart();
                this.createServiceChart();
                this.createTimeChart();
                this.createAttackerChart();
                // Populate initial data
                this.updateCharts();
            }

            updateTimezoneIndicator() {
                const indicator = document.getElementById('timezone-indicator');
                if (indicator) {
                    // Get timezone abbreviation/name
                    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
                    const now = new Date();
                    const tzOffset = now.getTimezoneOffset();
                    const offsetHours = Math.floor(Math.abs(tzOffset) / 60);
                    const offsetMins = Math.abs(tzOffset) % 60;
                    const offsetSign = tzOffset <= 0 ? '+' : '-';
                    const offsetStr = `UTC${offsetSign}${offsetHours.toString().padStart(2, '0')}:${offsetMins.toString().padStart(2, '0')}`;
                    indicator.textContent = `(${timezone} - ${offsetStr})`;
                }
            }

            // Compute derived summary data from the attacks array
            computeDerivedSummary() {
                const attacks = this.data.attacks || [];
                const summary = {
                    total_attacks: attacks.length,
                    unique_ips: 0,
                    services_targeted: {},
                    countries: {},
                    top_attackers: {},
                    hourlyStats: {}
                };

                const ips = new Set();
                attacks.forEach(a => {
                    if (a.src_ip) ips.add(a.src_ip);
                    const svc = (a.service || 'unknown').toUpperCase();
                    summary.services_targeted[svc] = (summary.services_targeted[svc] || 0) + 1;
                    const country = a.country || 'Unknown';
                    summary.countries[country] = (summary.countries[country] || 0) + 1;
                    const attacker = a.src_ip || 'unknown';
                    summary.top_attackers[attacker] = (summary.top_attackers[attacker] || 0) + 1;
                    // Use parseTimestamp to handle timezone conversion properly
                    const dt = parseTimestamp(a.timestamp || Date.now());
                    // Create hour bucket in visitor's local timezone
                    const year = dt.getFullYear();
                    const month = String(dt.getMonth() + 1).padStart(2, '0');
                    const day = String(dt.getDate()).padStart(2, '0');
                    const hour = String(dt.getHours()).padStart(2, '0');
                    const hourKey = `${year}-${month}-${day} ${hour}:00`;
                    summary.hourlyStats[hourKey] = (summary.hourlyStats[hourKey] || 0) + 1;
                });

                summary.unique_ips = ips.size;
                return summary;
            }

            updateCharts() {
                // Create hybrid summary: use original data when available, compute missing parts
                let summary;
                if (this.data.summary && this.data.summary.total_attacks) {
                    // Use original summary data from JSON file
                    summary = { ...this.data.summary };
                    
                    // Use real hourly stats if available, otherwise compute from attacks array
                    if (this.data.hourlyStats && Object.keys(this.data.hourlyStats).length > 0) {
                        summary.hourlyStats = this.data.hourlyStats;
                    } else {
                        // Fallback: compute hourlyStats from attacks array
                        const computedSummary = this.computeDerivedSummary();
                        summary.hourlyStats = computedSummary.hourlyStats;
                    }
                } else {
                    // Fallback to computed data from attacks array
                    summary = this.computeDerivedSummary();
                }

                // Country doughnut - sorted by attack count (descending)
                if (this.charts.country) {
                    const countryEntries = Object.entries(summary.countries)
                        .sort((a, b) => b[1] - a[1]); // Sort by attack count descending
                    const labels = countryEntries.map(e => e[0]);
                    const data = countryEntries.map(e => e[1]);
                    const colors = this.generateColors(labels.length);
                    
                    this.charts.country.data.labels = labels;
                    this.charts.country.data.datasets[0].data = data;
                    this.charts.country.data.datasets[0].backgroundColor = colors;
                    this.charts.country.update();
                }

                // Service bar - sorted by attack count (descending)
                if (this.charts.service) {
                    const serviceEntries = Object.entries(summary.services_targeted || {})
                        .sort((a, b) => b[1] - a[1]); // Sort by attack count descending
                    const svcLabels = serviceEntries.map(e => e[0]);
                    const svcData = serviceEntries.map(e => e[1]);
                    this.charts.service.data.labels = svcLabels.map(s => s.toUpperCase());
                    this.charts.service.data.datasets[0].data = svcData;
                    this.charts.service.update();
                }

                // Time line chart (sorted by hour) - Filter to show only recent hours
                if (this.charts.time) {
                    // Determine how many hours to show based on screen size
                    const isMobile = window.innerWidth <= 768;
                    const hoursToShow = isMobile ? 8 : 12; // 8 hours on mobile, 12 on desktop
                    
                    const allHours = Object.keys(summary.hourlyStats || {}).sort();
                    
                    // Filter to show only the most recent X hours
                    const recentHours = allHours.slice(-hoursToShow);
                    
                    // Format labels to show date and time more clearly
                    const hourLabels = recentHours.map(h => {
                        if (h.includes(' ')) {
                            // Format: "2025-08-27 10:00" -> "27/8 10:00"
                            const [datePart, timePart] = h.split(' ');
                            const [year, month, day] = datePart.split('-');
                            return `${day}/${month} ${timePart}`;
                        } else {
                            // Fallback for other formats
                            return h;
                        }
                    });
                    
                    const hourData = recentHours.map(h => summary.hourlyStats[h] || 0);
                    this.charts.time.data.labels = hourLabels;
                    this.charts.time.data.datasets[0].data = hourData;
                    this.charts.time.update();
                }

                // Top attackers horizontal bar
                if (this.charts.attacker) {
                    // sort top 10
                    const entries = Object.entries(summary.top_attackers).sort((a,b) => b[1]-a[1]).slice(0,10);
                    const attackerLabels = entries.map(e => e[0]);
                    const attackerData = entries.map(e => e[1]);
                    this.charts.attacker.data.labels = attackerLabels;
                    this.charts.attacker.data.datasets[0].data = attackerData;
                    this.charts.attacker.update();
                }
            }

            // Generate colors dynamically for charts
            generateColors(count) {
                const baseColors = [
                    '#ff0080', '#00ff41', '#00b8ff', '#ffa500', 
                    '#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4',
                    '#f39c12', '#e74c3c', '#9b59b6', '#3498db',
                    '#2ecc71', '#f1c40f', '#e67e22', '#1abc9c'
                ];
                
                const colors = [];
                for (let i = 0; i < count; i++) {
                    if (i < baseColors.length) {
                        colors.push(baseColors[i]);
                    } else {
                        // Generate additional colors with HSL
                        const hue = (i * 137.508) % 360; // Golden angle approximation
                        const saturation = 70 + (i % 30);
                        const lightness = 50 + (i % 20);
                        colors.push(`hsl(${hue}, ${saturation}%, ${lightness}%)`);
                    }
                }
                return colors;
            }

            createCountryChart() {
                const ctx = document.getElementById('countryChart').getContext('2d');
                this.charts.country = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: [],
                        datasets: [{
                            data: [],
                            backgroundColor: [], // Will be generated dynamically
                            borderColor: '#000',
                            borderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: window.innerWidth > 768, // Maintain on desktop
                        aspectRatio: window.innerWidth <= 768 ? 1 : 1.2, // Square on mobile
                        plugins: {
                            legend: {
                                position: window.innerWidth <= 768 ? 'bottom' : 'right',
                                labels: {
                                    color: '#fff',
                                    usePointStyle: true,
                                    padding: window.innerWidth <= 768 ? 8 : 20,
                                    boxWidth: window.innerWidth <= 768 ? 12 : 15,
                                    font: {
                                        size: window.innerWidth <= 768 ? 10 : 12
                                    }
                                },
                                maxHeight: window.innerWidth <= 768 ? 150 : undefined,
                                overflow: window.innerWidth <= 768 ? 'scroll' : undefined
                            }
                        },
                        layout: {
                            padding: window.innerWidth <= 768 ? 5 : 10
                        }
                    }
                });
            }

            createServiceChart() {
                const ctx = document.getElementById('serviceChart').getContext('2d');
                this.charts.service = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: [],
                        datasets: [{
                            label: 'Attack Count',
                            data: [],
                            backgroundColor: 'rgba(0, 255, 65, 0.6)',
                            borderColor: '#00ff41',
                            borderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: window.innerWidth > 768, // Only maintain aspect ratio on desktop
                        aspectRatio: window.innerWidth <= 768 ? 1.5 : 2, // Better mobile ratio
                        indexAxis: window.innerWidth <= 768 ? 'y' : 'x', // Horizontal bars on mobile
                        scales: {
                            y: {
                                beginAtZero: true,
                                grid: {
                                    color: 'rgba(0, 255, 65, 0.1)'
                                },
                                ticks: {
                                    color: '#fff',
                                    font: {
                                        size: window.innerWidth <= 768 ? 10 : 12
                                    }
                                }
                            },
                            x: {
                                grid: {
                                    display: false
                                },
                                ticks: {
                                    color: '#fff',
                                    font: {
                                        size: window.innerWidth <= 768 ? 10 : 12
                                    }
                                }
                            }
                        },
                        plugins: {
                            legend: {
                                labels: {
                                    color: '#fff'
                                }
                            }
                        }
                    }
                });
            }

            createTimeChart() {
                const ctx = document.getElementById('timeChart').getContext('2d');
                const isMobile = window.innerWidth <= 768;
                
                this.charts.time = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: [],
                        datasets: [{
                            label: 'Attacks/Hour',
                            data: [],
                            borderColor: '#00b8ff',
                            backgroundColor: 'rgba(0, 184, 255, 0.1)',
                            borderWidth: 3,
                            fill: true,
                            tension: 0.4,
                            pointBackgroundColor: '#00b8ff',
                            pointBorderColor: '#fff',
                            pointBorderWidth: 2,
                            pointRadius: isMobile ? 4 : 5,
                            pointHoverRadius: isMobile ? 6 : 8
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: !isMobile, // Allow flexible height on mobile
                        aspectRatio: isMobile ? 1.5 : 2.2, // Better ratios for limited data
                        scales: {
                            y: {
                                beginAtZero: true,
                                grid: {
                                    color: 'rgba(0, 184, 255, 0.1)'
                                },
                                ticks: {
                                    color: '#fff',
                                    font: {
                                        size: isMobile ? 10 : 12
                                    }
                                }
                            },
                            x: {
                                grid: {
                                    color: 'rgba(0, 184, 255, 0.1)'
                                },
                                ticks: {
                                    color: '#fff',
                                    font: {
                                        size: isMobile ? 9 : 11
                                    },
                                    maxTicksLimit: isMobile ? 6 : 10, // Fewer ticks for cleaner look
                                    maxRotation: isMobile ? 45 : 0 // Allow rotation on mobile
                                }
                            }
                        },
                        plugins: {
                            legend: {
                                labels: {
                                    color: '#fff',
                                    font: {
                                        size: isMobile ? 11 : 14
                                    }
                                }
                            },
                            tooltip: {
                                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                                titleColor: '#00b8ff',
                                bodyColor: '#fff'
                            }
                        },
                        interaction: {
                            intersect: false,
                            mode: 'index'
                        }
                    }
                });
            }

            createAttackerChart() {
                const ctx = document.getElementById('attackerChart').getContext('2d');
                this.charts.attacker = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: [],
                        datasets: [{
                            label: 'Attack Count',
                            data: [],
                            backgroundColor: 'rgba(255, 0, 128, 0.6)',
                            borderColor: '#ff0080',
                            borderWidth: 2
                        }]
                    },
                    options: {
                        indexAxis: 'y',
                        responsive: true,
                        maintainAspectRatio: window.innerWidth > 768, // Only maintain on desktop
                        aspectRatio: window.innerWidth <= 768 ? 1 : 1.5, // Square-ish on mobile
                        scales: {
                            x: {
                                beginAtZero: true,
                                grid: {
                                    color: 'rgba(255, 0, 128, 0.1)'
                                },
                                ticks: {
                                    color: '#fff',
                                    font: {
                                        size: window.innerWidth <= 768 ? 10 : 12
                                    }
                                }
                            },
                            y: {
                                grid: {
                                    display: false
                                },
                                ticks: {
                                    color: '#fff',
                                    font: {
                                        size: window.innerWidth <= 768 ? 8 : 12
                                    }
                                }
                            }
                        },
                        plugins: {
                            legend: {
                                labels: {
                                    color: '#fff'
                                }
                            }
                        }
                    }
                });
            }

            populateTable() {
                console.log('populateTable called - showing both attacks and binaries');
                this.populateAttacksTable();
                this.populateBinariesTable();
            }

            populateAttacksTable() {
                console.log('populateAttacksTable called');
                const tbody = document.getElementById('attacks-tbody');
                const cardsContainer = document.getElementById('attacks-cards');
                console.log('Cards container found:', !!cardsContainer);
                
                // Force mobile view detection
                const isMobile = window.innerWidth <= 768 || /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
                console.log('Is mobile device:', isMobile, 'Screen width:', window.innerWidth);
                
                if (isMobile) {
                    // Force mobile styles with JavaScript
                    const table = document.querySelector('#attacks table');
                    const cards = document.querySelector('#attacks-cards');
                    console.log('Attack table found:', !!table);
                    console.log('Attack cards found:', !!cards);
                    if (table) {
                        table.style.display = 'none';
                        console.log('Attack table hidden for mobile');
                    }
                    if (cards) {
                        cards.style.display = 'block';
                        cards.style.padding = '10px';
                        console.log('Attack cards shown for mobile');
                    }
                }
                
                tbody.innerHTML = '';
                cardsContainer.innerHTML = '';

                // Get attack data
                const attackData = this.data.attacks || [];
                
                if (!attackData || attackData.length === 0) {
                    const row = tbody.insertRow();
                    row.innerHTML = '<td colspan="6" class="no-data" style="text-align: center; padding: 30px;">No attack data available</td>';
                    
                    const placeholderCard = document.createElement('div');
                    placeholderCard.className = 'attack-card';
                    placeholderCard.innerHTML = `
                        <div style="color: white; font-size: 16px; padding: 20px; text-align: center;">
                            <h3>No recent attacks</h3>
                            <p>Attack vectors will appear here when detected.</p>
                        </div>
                    `;
                    cardsContainer.appendChild(placeholderCard);
                    return;
                }

                // Show last 10 attacks
                const recentAttacks = attackData.slice(-10).reverse();
                console.log('Creating cards for', recentAttacks.length, 'attacks');
                
                recentAttacks.forEach((attack, index) => {
                    // Populate table row (desktop)
                    const row = tbody.insertRow();
                    row.setAttribute('data-reveal', '');
                    
                    row.innerHTML = `
                        <td>${parseTimestamp(attack.timestamp).toLocaleString()}</td>
                        <td class="ip-cell">${attack.src_ip || 'Unknown'}</td>
                        <td class="service-cell">${(attack.service || 'unknown').toUpperCase()}</td>
                        <td>${attack.dst_port || 'Unknown'}</td>
                        <td class="country-cell">${attack.country || 'Unknown'}</td>
                        <td class="city-cell">${attack.city || 'Unknown'}</td>
                    `;
                    
                    // Add row animation
                    row.style.opacity = '0';
                    row.style.transform = 'translateX(-20px)';
                    setTimeout(() => {
                        row.style.transition = 'all 0.5s ease';
                        row.style.opacity = '1';
                        row.style.transform = 'translateX(0)';
                    }, index * 50);

                    // Populate card (mobile)
                    const card = document.createElement('div');
                    card.className = 'attack-card';
                    card.setAttribute('data-reveal', '');
                    
                    const severity = this.getAttackSeverity(attack.service);
                    
                    card.innerHTML = `
                        <div class="attack-card-header">
                            <div class="attack-timestamp">
                                <i class="fas fa-clock"></i>
                                ${parseTimestamp(attack.timestamp).toLocaleString()}
                            </div>
                            <div class="attack-severity">${severity}</div>
                        </div>
                        
                        <div class="attack-details">
                            <div class="attack-detail">
                                <div class="attack-detail-label">
                                    <i class="fas fa-map-marker-alt"></i>
                                    Source IP
                                </div>
                                <div class="attack-detail-value ip">${attack.src_ip || 'Unknown'}</div>
                            </div>
                            
                            <div class="attack-detail">
                                <div class="attack-detail-label">
                                    <i class="fas fa-cog"></i>
                                    Service
                                </div>
                                <div class="attack-detail-value service">${(attack.service || 'unknown').toUpperCase()}</div>
                            </div>
                            
                            <div class="attack-detail">
                                <div class="attack-detail-label">
                                    <i class="fas fa-plug"></i>
                                    Port
                                </div>
                                <div class="attack-detail-value port">${attack.dst_port || 'Unknown'}</div>
                            </div>
                            
                            <div class="attack-detail">
                                <div class="attack-detail-label">
                                    <i class="fas fa-flag"></i>
                                    Location
                                </div>
                                <div class="attack-detail-value location">${attack.city || 'Unknown'}, ${attack.country || 'Unknown'}</div>
                            </div>
                        </div>
                    `;
                    
                    cardsContainer.appendChild(card);
                    console.log('Attack card created and appended:', index + 1);
                });
                
                // Remove animation classes from cards
                const cards = document.querySelectorAll('#attacks .attack-card');
                cards.forEach(card => {
                    card.style.opacity = '1';
                    card.style.transform = 'none';
                    card.style.transition = 'none';
                });
            }

            populateBinariesTable() {
                const tbody = document.getElementById('binaries-tbody');
                const cardsContainer = document.getElementById('binaries-cards');
                
                // Force mobile view detection
                const isMobile = window.innerWidth <= 768 || /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
                
                if (isMobile) {
                    // Force mobile styles with JavaScript
                    const table = document.querySelector('#binaries table');
                    const cards = document.querySelector('#binaries-cards');
                    if (table) {
                        table.style.display = 'none';
                    }
                    if (cards) {
                        cards.style.display = 'block';
                        cards.style.padding = '10px';
                    }
                }
                
                tbody.innerHTML = '';
                cardsContainer.innerHTML = '';

                // Get binary data from summary
                const binaryData = this.data.summary?.binary_stats?.recent_binaries || [];
                
                if (!binaryData || binaryData.length === 0) {
                    const row = tbody.insertRow();
                    row.innerHTML = '<td colspan="5" class="no-data" style="text-align: center; padding: 30px;">No binary data available</td>';
                    
                    // Add a placeholder card if no binary data is available
                    const placeholderCard = document.createElement('div');
                    placeholderCard.className = 'attack-card';
                    placeholderCard.innerHTML = `
                        <div style="color: white; font-size: 16px; padding: 20px; text-align: center;">
                            <h3>No binary captures available</h3>
                            <p>Binary data will appear here once malware is captured.</p>
                        </div>
                    `;
                    cardsContainer.appendChild(placeholderCard);
                    return;
                }

                console.log('Creating cards for', binaryData.length, 'binaries');
                
                binaryData.forEach((binary, index) => {
                    // Populate table row (desktop)
                    const row = tbody.insertRow();
                    row.setAttribute('data-reveal', '');
                    
                    // Format file size
                    const formatSize = (bytes) => {
                        if (bytes === 0) return '0 B';
                        const k = 1024;
                        const sizes = ['B', 'KB', 'MB', 'GB'];
                        const i = Math.floor(Math.log(bytes) / Math.log(k));
                        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
                    };
                    
                    row.innerHTML = `
                        <td>${parseTimestamp(binary.timestamp).toLocaleString()}</td>
                        <td class="filename-cell">${binary.filename || 'Unknown'}</td>
                        <td class="filetype-cell">${(binary.file_type || 'unknown').replace(/_/g, ' ')}</td>
                        <td>${formatSize(binary.size || 0)}</td>
                        <td class="hash-cell">${(binary.hash || 'Unknown').substring(0, 8)}...</td>
                    `;
                    
                    // Add row animation
                    row.style.opacity = '0';
                    row.style.transform = 'translateX(-20px)';
                    setTimeout(() => {
                        row.style.transition = 'all 0.5s ease';
                        row.style.opacity = '1';
                        row.style.transform = 'translateX(0)';
                    }, index * 50);

                    // Populate card (mobile)
                    const card = document.createElement('div');
                    card.className = 'attack-card';
                    card.setAttribute('data-reveal', '');
                    
                    const fileType = (binary.file_type || 'unknown').replace(/_/g, ' ');
                    const severity = this.getBinarySeverity(fileType);
                    
                    card.innerHTML = `
                        <div class="attack-card-header">
                            <div class="attack-timestamp">
                                <i class="fas fa-clock"></i>
                                ${parseTimestamp(binary.timestamp).toLocaleString()}
                            </div>
                            <div class="attack-severity">${severity}</div>
                        </div>
                        
                        <div class="attack-details">
                            <div class="attack-detail">
                                <div class="attack-detail-label">
                                    <i class="fas fa-file"></i>
                                    Filename
                                </div>
                                <div class="attack-detail-value filename">${binary.filename || 'Unknown'}</div>
                            </div>
                            
                            <div class="attack-detail">
                                <div class="attack-detail-label">
                                    <i class="fas fa-tag"></i>
                                    File Type
                                </div>
                                <div class="attack-detail-value filetype">${fileType}</div>
                            </div>
                            
                            <div class="attack-detail">
                                <div class="attack-detail-label">
                                    <i class="fas fa-hdd"></i>
                                    Size
                                </div>
                                <div class="attack-detail-value">${formatSize(binary.size || 0)}</div>
                            </div>
                            
                            <div class="attack-detail">
                                <div class="attack-detail-label">
                                    <i class="fas fa-fingerprint"></i>
                                    Hash
                                </div>
                                <div class="attack-detail-value hash">${(binary.hash || 'Unknown').substring(0, 16)}...</div>
                            </div>
                        </div>
                    `;
                    
                    cardsContainer.appendChild(card);
                });
                
                // Remove animation classes from cards
                const cards = document.querySelectorAll('#binaries .attack-card');
                cards.forEach(card => {
                    card.style.opacity = '1';
                    card.style.transform = 'none';
                    card.style.transition = 'none';
                });
            }

            getAttackSeverity(service) {
                const highRisk = ['ssh', 'rdp', 'smb', 'mysql', 'mssql'];
                const mediumRisk = ['http', 'https', 'ftp', 'telnet'];
                
                const svc = (service || '').toLowerCase();
                if (highRisk.includes(svc)) return 'HIGH';
                if (mediumRisk.includes(svc)) return 'MEDIUM';
                return 'LOW';
            }

            getBinarySeverity(fileType) {
                const highRisk = ['PE executable', 'ELF executable', 'shell script'];
                const mediumRisk = ['ZIP archive', 'GZIP archive', 'RAR archive'];
                
                if (highRisk.some(risk => fileType.toLowerCase().includes(risk.toLowerCase()))) return 'HIGH';
                if (mediumRisk.some(risk => fileType.toLowerCase().includes(risk.toLowerCase()))) return 'MEDIUM';
                return 'LOW';
            }

            updateStats() {
                // Only compute derived summary if we don't have real summary data
                if (!this.data.summary || !this.data.summary.total_attacks) {
                    this.data.summary = this.computeDerivedSummary();
                }
                
                const stats = [
                    { id: 'total-attacks', value: this.data.summary.total_attacks || 0 },
                    { id: 'unique-ips', value: this.data.summary.unique_ips || 0 },
                    { id: 'binaries-count', value: this.data.summary.total_binaries || 0 },
                    { id: 'countries-count', value: Object.keys(this.data.summary.countries || {}).length }
                ];

                stats.forEach(stat => {
                    this.animateNumber(stat.id, stat.value);
                });

                // Update last updated timestamp with actual data time (not current time)
                const lastUpdated = document.getElementById('last-updated');
                if (lastUpdated) {
                    // Use the timestamp from the most recent attack data, or current time if no data
                    const updateTime = this.lastDataUpdateTime || new Date();
                    lastUpdated.textContent = `LAST MATRIX UPDATE: ${updateTime.toLocaleString()}`;
                }
            }

            animateNumber(elementId, targetValue) {
                const element = document.getElementById(elementId);
                if (!element) return;
                
                // Check if we already have this target value
                if (this.currentStatValues[elementId] === targetValue) {
                    return; // No change, skip animation
                }
                
                const startValue = this.currentStatValues[elementId] || 0;
                
                // Update our tracked value immediately
                this.currentStatValues[elementId] = targetValue;
                
                // Skip animation if no change from the actual tracked value
                if (startValue === targetValue) {
                    element.textContent = targetValue.toLocaleString();
                    return;
                }
                
                // Add flash effect for changes
                element.style.transition = 'all 0.3s ease';
                element.style.color = '#00ff41';
                element.style.transform = 'scale(1.1)';
                
                const duration = Math.min(800, Math.abs(targetValue - startValue) * 50); // Faster for smaller changes
                const stepTime = 16; // 60fps
                const steps = duration / stepTime;
                const stepValue = (targetValue - startValue) / steps;

                let currentStep = 0;
                const timer = setInterval(() => {
                    currentStep++;
                    const currentValue = Math.floor(startValue + (stepValue * currentStep));
                    element.textContent = currentValue.toLocaleString();

                    if (currentStep >= steps) {
                        clearInterval(timer);
                        element.textContent = targetValue.toLocaleString();
                        
                        // Reset flash effect
                        setTimeout(() => {
                            element.style.color = '';
                            element.style.transform = '';
                        }, 300);
                    }
                }, stepTime);
            }

            startTerminalFeed() {
                const terminalContent = document.getElementById('terminal-content');
                
                // Initialize baseline - capture current attacks so we only show NEW ones
                this.previousAttacks = [...(this.data.attacks || [])];
                
                // Initialize pending attacks queue for 30-second delay
                this.pendingAttacks = [];
                
                // Add welcome message to terminal
                const welcomeLine = document.createElement('div');
                welcomeLine.classList.add('terminal-line');
                welcomeLine.style.color = '#00ff41';
                welcomeLine.textContent = `[${new Date().toLocaleTimeString()}] HONEYPOT MATRIX INITIALIZED - MONITORING FOR NEW THREATS...`;
                terminalContent.appendChild(welcomeLine);
                this.terminalLines.push(welcomeLine);
                
                const pushLine = (text) => {
                    // keep terminal capped
                    while (this.terminalLines.length > 100) {
                        const first = this.terminalLines.shift();
                        if (first && first.parentNode) first.parentNode.removeChild(first);
                    }

                    const line = document.createElement('div');
                    line.classList.add('terminal-line');
                    line.textContent = text;
                    terminalContent.appendChild(line);
                    this.terminalLines.push(line);
                    terminalContent.scrollTop = terminalContent.scrollHeight;
                };

                // Polling-only feed (no WebSocket)
                const feedStatusEl = document.getElementById('feed-status');
                const setFeedStatus = (txt) => { 
                    if (feedStatusEl) {
                        feedStatusEl.textContent = txt;
                    }
                };
                setFeedStatus('Live Feed');

                // Process pending attacks every second for MAP VISUALIZATION ONLY (30s delay)
                const processPendingAttacks = () => {
                    const now = Date.now();
                    const attacksToVisualize = [];
                    
                    // Update pending counter for MAP queue
                    const pendingCounter = document.getElementById('map-pending-counter');
                    if (pendingCounter) {
                        pendingCounter.textContent = `Queue: ${this.pendingAttacks.length}`;
                    }
                    
                    // Find attacks ready for MAP visualization (30 seconds after their timestamp)
                    this.pendingAttacks = this.pendingAttacks.filter(attack => {
                        const attackTime = parseTimestamp(attack.timestamp).getTime();
                        const visualizeTime = attackTime + 30000; // 30 seconds delay for MAP only
                        
                        if (now >= visualizeTime) {
                            attacksToVisualize.push(attack);
                            return false; // Remove from pending
                        }
                        return true; // Keep in pending
                    });
                    
                    // Visualize ready attacks on MAP only
                    attacksToVisualize.forEach(attack => {
                        console.log(`Visualizing attack on map after 30s delay:`, attack.src_ip, attack.country);
                        // Add animated curved arrow to map
                        this.addMapAttackWithAnimation(attack);
                    });
                };

                // Start processing pending attacks
                setInterval(processPendingAttacks, 1000);

                let pollNotified = false;
                const poll = async () => {
                    try {
                        // Fetch both attacks and summary data to ensure real-time updates
                        const [attacksRes, summaryRes] = await Promise.all([
                            fetch('./data/attacks.json?t=' + Date.now()),
                            fetch('./data/summary.json?t=' + Date.now()).catch(() => null)
                        ]);
                        
                        if (!attacksRes.ok) return;
                        const attacks = await attacksRes.json();
                        
                        // Update summary data if available
                        if (summaryRes && summaryRes.ok) {
                            const summaryData = await summaryRes.json();
                            this.data.summary = summaryData;
                        }
                        
                        // Check if we have new data
                        const currentDataLength = this.data.attacks ? this.data.attacks.length : 0;
                        const hasNewData = attacks.length !== currentDataLength;
                        
                        // Always update the attacks data
                        this.data.attacks = attacks;
                        
                        // Only update the last data time when we actually receive new data
                        if (hasNewData && attacks.length > 0) {
                            const latestAttack = attacks[attacks.length - 1];
                            this.lastDataUpdateTime = parseTimestamp(latestAttack.timestamp);
                        }
                        
                        // Always update stats and charts for real-time display
                        this.updateStats();
                        this.updateCharts();
                        
                        // find new entries for terminal feed and map
                        const known = new Set((this.previousAttacks || []).map(a => `${a.timestamp}|${a.src_ip}`));
                        const newAttacks = attacks.filter(a => !known.has(`${a.timestamp}|${a.src_ip}`));
                        
                        // Only update table if there are new attacks or if it's the first load
                        if (newAttacks.length > 0 || !this.previousAttacks) {
                            this.populateTable();
                        }
                        
                        // Process new attacks: immediate terminal feed + delayed map visualization
                        if (newAttacks.length > 0) {
                            newAttacks.forEach(attack => {
                                // IMMEDIATE: Add to terminal feed right away
                                const ts = parseTimestamp(attack.timestamp).toLocaleTimeString();
                                const svc = (attack.service || 'unknown').toUpperCase();
                                const country = attack.country || 'Unknown';
                                pushLine(`[${ts}] ALERT: ${svc} attack from ${attack.src_ip || 'unknown'} (${country}) -> port ${attack.dst_port || 'unknown'}`);
                                
                                // DELAYED: Add to pending queue for map visualization (30s delay)
                                this.pendingAttacks.push(attack);
                                console.log(`New attack: Terminal=${ts}, Map queued for 30s delay:`, attack.src_ip, attack.country, attack.service);
                            });
                        }
                        
                        this.previousAttacks = attacks.slice();
                        
                        if (!pollNotified) {
                            // suppress terminal status line; update only badge
                            pollNotified = true;
                        }
                    } catch (e) { console.warn('polling error', e); }
                };

                // Run initial poll immediately and then every 2 seconds for real-time updates
                poll();
                const pollingInterval = setInterval(poll, 2000);

                // Clean up if needed when page unloads
                window.addEventListener('beforeunload', () => {
                    clearInterval(pollingInterval);
                });
            }

            hideLoading() {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('dashboard-content').style.display = 'block';
            }

            showError(message) {
                const loading = document.getElementById('loading');
                loading.innerHTML = `
                    <div class="error">
                        <i class="fas fa-exclamation-triangle"></i> 
                        ${message}
                        <br><br>
                        <small>Make sure your Raspberry Pi is uploading data to ./data/ directory</small>
                    </div>
                `;
            }
        }

        // Initialize everything when page loads
        document.addEventListener('DOMContentLoaded', () => {
            // Initialize matrix effect
            createMatrixRain();
            
            // Initialize scroll progress bar
            initScrollProgress();
            
            // Mobile navigation
            const menuToggle = document.getElementById('menu-toggle');
            const navLinks = document.getElementById('nav-links');
            
            if (menuToggle && navLinks) {
                menuToggle.addEventListener('click', () => {
                    menuToggle.classList.toggle('active');
                    navLinks.classList.toggle('active');
                });

                // Close menu when clicking on a link
                navLinks.querySelectorAll('a').forEach(link => {
                    link.addEventListener('click', () => {
                        menuToggle.classList.remove('active');
                        navLinks.classList.remove('active');
                    });
                });

                // Close menu when clicking outside
                document.addEventListener('click', (e) => {
                    if (!document.querySelector('.header').contains(e.target)) {
                        menuToggle.classList.remove('active');
                        navLinks.classList.remove('active');
                    }
                });
            }
            
            // Initialize everything when DOM is ready
            document.addEventListener('DOMContentLoaded', function() {
                // Smooth scrolling for nav links
                document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                    anchor.addEventListener('click', function (e) {
                        e.preventDefault();
                        const target = document.querySelector(this.getAttribute('href'));
                        if (!target) return; // Target section not found

                        const headerHeight = document.querySelector('.header').offsetHeight;
                        const targetPosition = target.getBoundingClientRect().top + window.scrollY - headerHeight - 10;

                        window.scrollTo({
                            top: targetPosition,
                            behavior: 'smooth'
                        });
                    });
                });
                
                // Initialize mobile menu toggle
                const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
                const navLinks = document.querySelector('.nav-links');
                
                if (mobileMenuBtn && navLinks) {
                    mobileMenuBtn.addEventListener('click', function() {
                        this.classList.toggle('active');
                        navLinks.classList.toggle('active');
                    });
                    
                    // Close mobile menu when clicking on a link
                    navLinks.querySelectorAll('a').forEach(link => {
                        link.addEventListener('click', function() {
                            mobileMenuBtn.classList.remove('active');
                            navLinks.classList.remove('active');
                        });
                    });
                }
                
                // Initialize honeypot dashboard with debugging
                console.log('DOM loaded, initializing honeypot dashboard...');
                try {
                    window.honeypot = new HoneypotMatrix();
                    console.log('HoneypotMatrix created successfully');
                } catch (error) {
                    console.error('Failed to create HoneypotMatrix:', error);
                    // Force hide loading screen on error
                    setTimeout(() => {
                        const loading = document.getElementById('loading');
                        const content = document.getElementById('dashboard-content');
                        if (loading) loading.style.display = 'none';
                        if (content) content.style.display = 'block';
                    }, 1000);
                }
            });
            
            // Fallback initialization after 2 seconds if DOMContentLoaded doesn't work
            setTimeout(() => {
                if (!window.honeypot) {
                    console.log('Fallback initialization triggered...');
                    try {
                        window.honeypot = new HoneypotMatrix();
                    } catch (error) {
                        console.error('Fallback initialization failed:', error);
                        // Force show dashboard even if broken
                        const loading = document.getElementById('loading');
                        const content = document.getElementById('dashboard-content');
                        if (loading) loading.style.display = 'none';
                        if (content) content.style.display = 'block';
                    }
                }
            }, 2000);
            
            // Keep the old initialization as fallback
            // Smooth scrolling for nav links (fallback)
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', function (e) {
                    e.preventDefault();
                    const target = document.querySelector(this.getAttribute('href'));
                    if (!target) return; // target missing (map removed)
                    
                    const headerHeight = document.querySelector('.header').offsetHeight;
                    const targetPosition = target.offsetTop - headerHeight - 20;
                    
                    window.scrollTo({
                        top: targetPosition,
                        behavior: 'smooth'
                    });
                });
            });

            // Reveal on scroll using IntersectionObserver
            const revealObserver = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('visible');
                        // if element has children with data-reveal, stagger them
                        const staged = entry.target.querySelectorAll('[data-reveal]');
                        staged.forEach((el, i) => {
                            setTimeout(() => el.classList.add('visible'), i * 80);
                        });
                        // unobserve once visible
                        revealObserver.unobserve(entry.target);
                    }
                });
            }, { threshold: 0.12 });

            // Elements to reveal
            const revealSelectors = [
                '.stat-card',
                '.chart-container',
                '.terminal',
                '.attacks-table',
                '.hero-content'
            ];

            revealSelectors.forEach(sel => {
                document.querySelectorAll(sel).forEach(el => {
                    el.classList.add('reveal');
                    revealObserver.observe(el);
                });
            });

            // Stagger stat-card children
            document.querySelectorAll('.stats-grid .stat-card').forEach((card, i) => {
                card.setAttribute('data-reveal', '');
            });

            // Stagger chart containers
            document.querySelectorAll('.charts-grid .chart-container').forEach((c, i) => {
                c.setAttribute('data-reveal', '');
            });
        });
        
        // Emergency fallback - force load after 2 seconds no matter what
        setTimeout(() => {
            console.log('Emergency fallback triggered - forcing dashboard to show');
            const loading = document.getElementById('loading');
            const content = document.getElementById('dashboard-content');
            if (loading && loading.style.display !== 'none') {
                console.log('Loading screen still visible, forcing hide...');
                loading.style.display = 'none';
                if (content) content.style.display = 'block';
                
                // Try to initialize if not already done
                if (!window.honeypot) {
                    console.log('Creating emergency HoneypotMatrix instance...');
                    try {
                        window.honeypot = new HoneypotMatrix();
                    } catch (e) {
                        console.error('Emergency initialization failed:', e);
                    }
                }
            }
        }, 2000);

        // Ensure loading screen is hidden even if initialization fails
        setTimeout(() => {
            const loading = document.getElementById('loading');
            const content = document.getElementById('dashboard-content');
            if (loading && loading.style.display !== 'none') {
                console.log('Forcing loading screen to hide due to timeout...');
                loading.style.display = 'none';
                if (content) content.style.display = 'block';
            }
        }, 3000);

        // Ensure cards are displayed on mobile devices
        const cardsContainer = document.getElementById('attacks-cards');
        if (cardsContainer) {
            cardsContainer.style.display = 'block';
            cardsContainer.style.padding = '10px';
        }