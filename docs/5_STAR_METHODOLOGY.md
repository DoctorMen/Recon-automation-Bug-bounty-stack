<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ScopeLock Security Assessment</title>
    <style>
        @page { size: A4; margin: 0; }
        body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial; }
        .cover { 
            width: 100%; 
            height: 100vh; 
            background: linear-gradient(135deg, #0c0f14 0%, #1a1f2e 50%, #0c0f14 100%);
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
            color: white;
            position: relative;
            overflow: hidden;
        }
        .logo { 
            width: 150px; 
            height: 150px; 
            background: linear-gradient(135deg, #66e0ff, #9a6bff);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 72px;
            font-weight: 900;
            color: white;
            margin-bottom: 32px;
            box-shadow: 0 20px 60px rgba(102,224,255,0.4);
        }
        h1 { 
            font-size: 48px; 
            font-weight: 900; 
            margin: 0 0 16px;
            background: linear-gradient(135deg, #fff, #66e0ff);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
        }
        .subtitle { 
            font-size: 24px; 
            color: #aab3c5; 
            margin: 0 0 48px;
            font-weight: 300;
        }
        .cert-box {
            background: rgba(255,255,255,0.05);
            border: 2px solid rgba(102,224,255,0.3);
            border-radius: 16px;
            padding: 32px 48px;
            margin: 32px 0;
            backdrop-filter: blur(10px);
        }
        .cert-title {
            font-size: 18px;
            color: #66e0ff;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 16px;
        }
        .client-name {
            font-size: 36px;
            font-weight: 700;
            margin: 8px 0;
        }
        .date {
            font-size: 16px;
            color: #aab3c5;
            margin-top: 16px;
        }
        .seal {
            position: absolute;
            bottom: 48px;
            right: 48px;
            width: 100px;
            height: 100px;
            background: linear-gradient(135deg, #66e0ff, #9a6bff);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            font-weight: 700;
            text-align: center;
            line-height: 1.2;
            box-shadow: 0 10px 30px rgba(102,224,255,0.5);
        }
        .qr {
            position: absolute;
            bottom: 48px;
            left: 48px;
            background: white;
            padding: 12px;
            border-radius: 8px;
        }
        .particles {
            position: absolute;
            width: 100%;
            height: 100%;
            overflow: hidden;
        }
        .particle {
            position: absolute;
            width: 2px;
            height: 2px;
            background: rgba(102,224,255,0.3);
            border-radius: 50%;
        }
    </style>
</head>
<body>
    <div class="cover">
        <div class="particles">
            <!-- Decorative particles -->
            <div class="particle" style="top:10%;left:15%;"></div>
            <div class="particle" style="top:20%;left:85%;"></div>
            <div class="particle" style="top:70%;left:10%;"></div>
            <div class="particle" style="top:80%;left:90%;"></div>
        </div>
        
        <div class="logo">SL</div>
        
        <h1>Security Assessment</h1>
        <p class="subtitle">Professional Penetration Testing Report</p>
        
        <div class="cert-box">
            <div class="cert-title">Assessed Organization</div>
            <div class="client-name">{{ company_name }}</div>
            <div class="date">Assessment Date: {{ assessment_date }}</div>
            <div class="date">Report ID: {{ report_id }}</div>
        </div>
        
        <div class="seal">
            CERTIFIED<br>
            SCOPELOCK<br>
            SECURITY
        </div>
        
        <div class="qr">
            <!-- QR code placeholder -->
            <img src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='80' height='80'%3E%3Crect width='80' height='80' fill='%23000'/%3E%3Ctext x='40' y='45' text-anchor='middle' fill='%23fff' font-size='10'%3EQR CODE%3C/text%3E%3C/svg%3E" width="80" height="80">
        </div>
    </div>
</body>
</html>

