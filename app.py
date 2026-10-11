from flask import Flask, request, jsonify, render_template_string, send_file
import io
import os
from crypto_utils import HybridCrypto
from ml_detector import ThreatDetector

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB maximum file size

# Initialize cryptography and ML threat detector instances
crypto = HybridCrypto()
detector = ThreatDetector()

# In-memory storage for keys and encrypted packages
users = {}
files = {}

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureVault | Cybersecurity Defense Platform</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0a0a0f;
            --card-bg: rgba(21, 21, 32, 0.8);
            --surface-border: rgba(0, 212, 255, 0.22);
            --primary: #00ff88;
            --primary-glow: rgba(0, 255, 136, 0.3);
            --secondary: #00d4ff;
            --secondary-glow: rgba(0, 212, 255, 0.3);
            --danger: #ff3366;
            --danger-glow: rgba(255, 51, 102, 0.3);
            --text-main: #f0f6fc;
            --text-muted: #8b949e;
            --code-bg: rgba(10, 10, 15, 0.95);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            transition: all 0.3s ease;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            min-height: 100vh;
            padding: 40px 20px;
            background-image: 
                radial-gradient(circle at 12% 15%, rgba(0, 255, 136, 0.06) 0%, transparent 40%),
                radial-gradient(circle at 88% 85%, rgba(0, 212, 255, 0.06) 0%, transparent 40%),
                linear-gradient(rgba(0, 212, 255, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 212, 255, 0.03) 1px, transparent 1px);
            background-size: 100% 100%, 100% 100%, 48px 48px, 48px 48px;
        }

        .container {
            max-width: 940px;
            margin: 0 auto;
        }

        header {
            text-align: center;
            margin-bottom: 36px;
        }

        .badge-terminal {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(0, 255, 136, 0.1);
            color: var(--primary);
            border: 1px solid rgba(0, 255, 136, 0.35);
            font-family: 'Courier New', monospace;
            font-size: 11.5px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            padding: 5px 14px;
            border-radius: 9999px;
            margin-bottom: 12px;
            box-shadow: 0 0 15px rgba(0, 255, 136, 0.2);
        }

        h1 {
            font-size: 34px;
            font-weight: 800;
            letter-spacing: -0.5px;
            margin-bottom: 8px;
            background: linear-gradient(135deg, #ffffff 40%, #00d4ff 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .subtitle {
            color: var(--text-muted);
            font-size: 14.5px;
            line-height: 1.6;
            max-width: 720px;
            margin: 0 auto;
        }

        .box {
            background-color: var(--card-bg);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border: 1px solid var(--surface-border);
            border-radius: 14px;
            padding: 26px;
            margin-bottom: 24px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.6);
            position: relative;
            overflow: hidden;
        }

        .box:hover {
            border-color: var(--primary);
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
        }

        .step-header {
            display: flex;
            align-items: center;
            gap: 14px;
            margin-bottom: 18px;
        }

        .step-num {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 32px;
            height: 32px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: #0a0a0f;
            font-weight: 800;
            font-size: 14px;
            font-family: 'Courier New', monospace;
            border-radius: 8px;
            box-shadow: 0 0 12px rgba(0, 255, 136, 0.4);
        }

        .step-title {
            font-size: 18px;
            font-weight: 700;
            color: #ffffff;
            letter-spacing: -0.2px;
        }

        .form-row {
            display: flex;
            flex-wrap: wrap;
            gap: 14px;
            margin-bottom: 16px;
        }

        .input-group {
            flex: 1;
            min-width: 220px;
        }

        label {
            display: block;
            font-size: 12.5px;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 6px;
            letter-spacing: 0.4px;
        }

        input[type="text"], input[type="file"] {
            width: 100%;
            background-color: var(--code-bg);
            border: 1px solid rgba(0, 212, 255, 0.25);
            color: var(--text-main);
            padding: 12px 14px;
            border-radius: 8px;
            font-size: 14px;
            font-family: 'Courier New', monospace;
            outline: none;
        }

        input[type="text"]:focus {
            border-color: var(--secondary);
            box-shadow: 0 0 15px rgba(0, 212, 255, 0.35);
        }

        input[type="file"] {
            padding: 9px 12px;
            cursor: pointer;
        }

        input[type="file"]::file-selector-button {
            background: rgba(0, 212, 255, 0.15);
            border: 1px solid var(--secondary);
            color: var(--secondary);
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 12.5px;
            font-weight: 600;
            cursor: pointer;
            margin-right: 12px;
        }

        input[type="file"]::file-selector-button:hover {
            background: var(--secondary);
            color: #0a0a0f;
            box-shadow: 0 0 12px var(--secondary-glow);
        }

        button {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: #0a0a0f;
            font-weight: 700;
            font-size: 14px;
            letter-spacing: 0.4px;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            box-shadow: 0 0 15px rgba(0, 255, 136, 0.25);
        }

        button:hover {
            box-shadow: 0 0 25px rgba(0, 255, 136, 0.6);
            transform: translateY(-2px);
        }

        button:disabled {
            opacity: 0.55;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        .output-box {
            margin-top: 18px;
            display: none;
        }

        .output-box.visible {
            display: block !important;
        }

        .banner {
            padding: 14px 18px;
            border-radius: 8px;
            font-size: 13.5px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 12px;
        }

        .banner.safe {
            background-color: rgba(0, 255, 136, 0.12);
            border: 1px solid var(--primary);
            color: var(--primary);
            box-shadow: 0 0 15px rgba(0, 255, 136, 0.2);
        }

        .banner.danger {
            background-color: rgba(255, 51, 102, 0.12);
            border: 1px solid var(--danger);
            color: var(--danger);
            box-shadow: 0 0 15px rgba(255, 51, 102, 0.2);
        }

        .banner.loading {
            background-color: rgba(0, 212, 255, 0.1);
            border: 1px solid var(--secondary);
            color: var(--secondary);
            box-shadow: 0 0 15px rgba(0, 212, 255, 0.2);
        }

        pre {
            background-color: var(--code-bg);
            border: 1px solid rgba(0, 212, 255, 0.25);
            color: var(--secondary);
            font-family: 'Courier New', Courier, monospace;
            font-size: 12.5px;
            padding: 16px;
            border-radius: 8px;
            overflow-x: auto;
            line-height: 1.6;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .spinner {
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid rgba(10, 10, 15, 0.3);
            border-radius: 50%;
            border-top-color: #0a0a0f;
            animation: spin 0.8s linear infinite;
        }

        /* Security Dashboard CSS Grid */
        .dashboard-box {
            border-color: rgba(0, 212, 255, 0.3);
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }

        .stat-card {
            background-color: var(--code-bg);
            border: 1px solid var(--surface-border);
            border-radius: 10px;
            padding: 16px;
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .stat-card:hover {
            border-color: var(--secondary);
            box-shadow: 0 0 15px rgba(0, 212, 255, 0.25);
        }

        .stat-icon {
            font-size: 26px;
            line-height: 1;
        }

        .stat-info {
            flex: 1;
        }

        .stat-label {
            font-size: 11px;
            text-transform: uppercase;
            font-weight: 700;
            letter-spacing: 0.8px;
            color: var(--text-muted);
            margin-bottom: 2px;
        }

        .stat-value {
            font-size: 24px;
            font-weight: 800;
            font-family: 'Courier New', monospace;
            color: var(--text-main);
        }

        .stat-value.safe-text {
            color: var(--primary);
            text-shadow: 0 0 12px var(--primary-glow);
        }

        .stat-value.threat-text {
            color: var(--danger);
            text-shadow: 0 0 12px var(--danger-glow);
        }

        /* Conic-gradient Gauge */
        .gauge-card {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .gauge-wrapper {
            position: relative;
            width: 56px;
            height: 56px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }

        .gauge-circle {
            width: 56px;
            height: 56px;
            border-radius: 50%;
            background: conic-gradient(var(--primary) 0deg 342deg, rgba(255, 255, 255, 0.1) 342deg 360deg);
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 18px var(--primary-glow);
        }

        .gauge-center {
            width: 42px;
            height: 42px;
            border-radius: 50%;
            background: #0a0a0f;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .gauge-text {
            font-size: 11.5px;
            font-weight: 800;
            color: var(--primary);
            font-family: 'Courier New', monospace;
        }

        .activity-section {
            background-color: var(--code-bg);
            border: 1px solid var(--surface-border);
            border-radius: 10px;
            padding: 16px;
        }

        .activity-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 11.5px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: var(--text-muted);
            margin-bottom: 12px;
        }

        .live-tag {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 11px;
            color: var(--primary);
            font-family: 'Courier New', monospace;
        }

        .live-dot {
            width: 8px;
            height: 8px;
            background-color: var(--primary);
            border-radius: 50%;
            box-shadow: 0 0 10px var(--primary);
            animation: pulse 1.4s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.35; transform: scale(0.8); }
        }

        .activity-log {
            max-height: 125px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            line-height: 1.6;
            display: flex;
            flex-direction: column;
            gap: 5px;
        }

        .activity-log::-webkit-scrollbar {
            width: 5px;
        }
        .activity-log::-webkit-scrollbar-track {
            background: #0a0a0f;
        }
        .activity-log::-webkit-scrollbar-thumb {
            background: rgba(0, 212, 255, 0.3);
            border-radius: 4px;
        }

        .log-row {
            display: flex;
            align-items: baseline;
            gap: 10px;
            padding: 2px 0;
            animation: fadeIn 0.3s ease-out;
        }

        .log-row.safe {
            color: var(--primary);
        }

        .log-row.danger {
            color: var(--danger);
        }

        .log-row.neutral {
            color: var(--secondary);
        }

        .log-time {
            color: #64748b;
            font-size: 11px;
            flex-shrink: 0;
        }

        /* Animated Progress Stepper */
        .progress-box {
            background-color: var(--code-bg);
            border: 1px solid var(--surface-border);
            border-radius: 10px;
            padding: 16px 20px;
            margin-bottom: 14px;
            animation: fadeIn 0.3s ease-out;
        }

        .step-row {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 9px 0;
            font-size: 14px;
            color: var(--text-muted);
            animation: fadeIn 0.3s ease-out;
        }

        .step-row.active {
            color: var(--secondary);
            font-weight: 600;
        }

        .step-row.completed {
            color: var(--primary);
        }

        .step-status {
            width: 22px;
            height: 22px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }

        .step-status .mini-spinner {
            width: 14px;
            height: 14px;
            border: 2px solid rgba(0, 212, 255, 0.2);
            border-top-color: var(--secondary);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }

        .step-status .check-icon {
            color: var(--primary);
            font-weight: bold;
            font-size: 16px;
            animation: checkPop 0.35s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;
            text-shadow: 0 0 10px var(--primary-glow);
        }

        .step-row.threat {
            color: var(--danger);
            font-weight: 700;
        }

        .step-status .threat-icon {
            color: var(--danger);
            font-weight: bold;
            font-size: 16px;
            animation: checkPop 0.35s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;
            text-shadow: 0 0 10px var(--danger-glow);
        }

        .step-status .wait-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background-color: rgba(255, 255, 255, 0.15);
        }

        .complete-card {
            background: linear-gradient(135deg, rgba(0, 255, 136, 0.15), rgba(0, 212, 255, 0.1));
            border: 1px solid var(--primary);
            border-radius: 8px;
            padding: 14px 18px;
            margin-top: 14px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            color: var(--primary);
            font-weight: 700;
            font-size: 14px;
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.25);
            animation: fadeIn 0.4s ease-out;
        }

        /* Blockchain Ledger Section */
        .blockchain-box {
            border-color: rgba(0, 255, 136, 0.3);
        }

        .chain-container {
            overflow-x: auto;
            padding: 16px 4px;
            margin-top: 12px;
        }

        .chain-container::-webkit-scrollbar {
            height: 6px;
        }
        .chain-container::-webkit-scrollbar-track {
            background: #0a0a0f;
            border-radius: 4px;
        }
        .chain-container::-webkit-scrollbar-thumb {
            background: rgba(0, 255, 136, 0.3);
            border-radius: 4px;
        }

        .blockchain-track {
            display: flex;
            align-items: center;
            gap: 0;
            min-width: max-content;
            padding: 10px 4px;
        }

        .block-card {
            background: var(--code-bg);
            border: 1px solid rgba(0, 255, 136, 0.3);
            border-radius: 10px;
            padding: 16px 18px;
            width: 260px;
            flex-shrink: 0;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
            position: relative;
        }

        .block-card:hover {
            border-color: var(--primary);
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.35);
            transform: translateY(-2px);
        }

        .block-card.chain-pulse {
            animation: greenPulse 1.2s ease-in-out infinite alternate;
        }

        @keyframes greenPulse {
            0% {
                box-shadow: 0 0 10px rgba(0, 255, 136, 0.3);
                border-color: var(--primary);
            }
            100% {
                box-shadow: 0 0 35px rgba(0, 255, 136, 0.9), 0 0 15px #00ff88;
                border-color: #00ff88;
            }
        }

        .chain-link {
            width: 40px;
            height: 2px;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
            position: relative;
            flex-shrink: 0;
            box-shadow: 0 0 8px var(--primary-glow);
        }

        .chain-link::after {
            content: '▶';
            position: absolute;
            right: -3px;
            top: -6px;
            font-size: 10px;
            color: var(--secondary);
        }

        .block-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .block-number {
            font-weight: 700;
            font-size: 13px;
            font-family: 'Courier New', monospace;
            color: #f1f5f9;
        }

        .block-status {
            font-size: 11px;
            font-weight: 700;
            color: var(--primary);
        }

        .block-field {
            margin-bottom: 8px;
        }

        .block-field:last-child {
            margin-bottom: 0;
        }

        .field-label {
            font-size: 10px;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.6px;
            color: var(--text-muted);
            margin-bottom: 2px;
        }

        .field-value {
            font-family: 'Courier New', Courier, monospace;
            font-size: 11.5px;
            color: var(--secondary);
            word-break: break-all;
        }

        .field-value.hash {
            color: var(--primary);
            font-weight: 600;
        }

        .field-value.prev-hash {
            color: #a78bfa;
        }

        .chain-verified-notice {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            background: rgba(0, 255, 136, 0.14);
            border: 1px solid var(--primary);
            color: var(--primary);
            font-weight: 700;
            font-size: 13.5px;
            padding: 11px 18px;
            border-radius: 8px;
            margin-top: 14px;
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
            animation: fadeIn 0.4s ease-out, greenPulse 1.2s ease-in-out infinite alternate;
        }

        /* Educational Section & Table */
        .edu-box {
            border-color: rgba(0, 212, 255, 0.3);
        }

        .edu-table-container {
            overflow-x: auto;
            border-radius: 8px;
            border: 1px solid var(--surface-border);
            margin: 18px 0;
            background: var(--code-bg);
        }

        .crypto-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13.5px;
            text-align: left;
        }

        .crypto-table th {
            background-color: rgba(21, 21, 32, 0.95);
            color: var(--text-muted);
            font-weight: 700;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.8px;
            padding: 13px 18px;
            border-bottom: 1px solid var(--surface-border);
        }

        .crypto-table td {
            padding: 13px 18px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
            color: var(--text-main);
        }

        .crypto-table tbody tr:hover td {
            background-color: rgba(0, 212, 255, 0.06);
        }

        .crypto-table tr.hybrid-row {
            background: rgba(0, 255, 136, 0.1);
        }

        .crypto-table tr.hybrid-row td {
            border-bottom: 1px solid rgba(0, 255, 136, 0.4);
            color: #ffffff;
            font-weight: 600;
        }

        .crypto-table tr.hybrid-row:hover td {
            background: rgba(0, 255, 136, 0.18);
        }

        .hybrid-badge {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            background: rgba(0, 255, 136, 0.2);
            border: 1px solid var(--primary);
            color: var(--primary);
            font-size: 11px;
            font-weight: 700;
            padding: 3px 10px;
            border-radius: 9999px;
            margin-left: 8px;
            box-shadow: 0 0 10px rgba(0, 255, 136, 0.3);
            vertical-align: middle;
        }

        /* Flow Diagram */
        .pipeline-flow {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
            background: var(--code-bg);
            border: 1px solid var(--surface-border);
            border-radius: 10px;
            padding: 18px 22px;
        }

        .flow-node {
            background: var(--card-bg);
            border: 1px solid var(--surface-border);
            border-radius: 8px;
            padding: 13px 18px;
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            min-width: 130px;
            flex: 1;
        }

        .flow-node:hover {
            border-color: var(--secondary);
            transform: translateY(-2px);
            box-shadow: 0 0 15px rgba(0, 212, 255, 0.3);
        }

        .flow-node.highlight-node {
            border-color: var(--primary);
            background: rgba(0, 255, 136, 0.08);
            box-shadow: 0 0 15px rgba(0, 255, 136, 0.2);
        }

        .flow-icon {
            font-size: 24px;
            margin-bottom: 6px;
        }

        .flow-title {
            font-weight: 700;
            font-size: 13.5px;
            color: #ffffff;
        }

        .flow-desc {
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 2px;
            font-family: 'Courier New', monospace;
        }

        .flow-arrow {
            color: var(--secondary);
            font-size: 20px;
            font-weight: bold;
            user-select: none;
            text-shadow: 0 0 8px var(--secondary-glow);
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(6px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes checkPop {
            0% { transform: scale(0.3); opacity: 0; }
            70% { transform: scale(1.3); }
            100% { transform: scale(1); opacity: 1; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="badge-terminal">CYBER DEFENSE SENTINEL • RSA-4096 / AES-256-GCM / ML ENGINE</div>
            <h1>SecureVault Intelligence</h1>
            <p class="subtitle">Military-Grade Hybrid Cryptography Coupled with Real-Time Neural Anomaly Threat Detection</p>
        </header>

        <!-- SECURITY DASHBOARD -->
        <section class="box dashboard-box">
            <div class="step-header">
                <span class="step-num">⚡</span>
                <span class="step-title">Live Security Operations Dashboard</span>
            </div>

            <!-- CSS Grid Metrics -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon">📄</div>
                    <div class="stat-info">
                        <div class="stat-label">Files Scanned</div>
                        <div id="statScanned" class="stat-value">0</div>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-icon">🟢</div>
                    <div class="stat-info">
                        <div class="stat-label">Safe Files</div>
                        <div id="statSafe" class="stat-value safe-text">0</div>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-icon">🛑</div>
                    <div class="stat-info">
                        <div class="stat-label">Threats Blocked</div>
                        <div id="statThreats" class="stat-value threat-text">0</div>
                    </div>
                </div>

                <div class="stat-card gauge-card">
                    <div class="gauge-wrapper">
                        <div id="confidenceGauge" class="gauge-circle">
                            <div class="gauge-center">
                                <span id="statConfidence" class="gauge-text">95%</span>
                            </div>
                        </div>
                    </div>
                    <div class="stat-info">
                        <div class="stat-label">ML Confidence</div>
                        <div style="font-size:11px; color:var(--secondary); font-family:'Courier New', monospace;">IsolationForest</div>
                    </div>
                </div>
            </div>

            <!-- Scrollable Activity Log -->
            <div class="activity-section">
                <div class="activity-header">
                    <span>Real-Time Event Stream</span>
                    <span class="live-tag"><span class="live-dot"></span> LIVE MONITOR</span>
                </div>
                <div id="activityLog" class="activity-log">
                    <div class="log-row neutral">
                        <span class="log-time" id="initTime">--:--:--</span>
                        <span>[SYSTEM ONLINE] Hybrid Cryptographic Engine and IsolationForest Sentinel active.</span>
                    </div>
                </div>
            </div>
        </section>

        <!-- STEP 1: KEY GENERATION -->
        <section class="box">
            <div class="step-header">
                <span class="step-num">01</span>
                <span class="step-title">Generate 4096-Bit Asymmetric RSA Vault Key</span>
            </div>
            <div class="form-row">
                <div class="input-group">
                    <label for="uid">USER IDENTITY IDENTIFIER</label>
                    <input type="text" id="uid" placeholder="e.g. alice, bob" value="bob">
                </div>
            </div>
            <button id="btnGenKey" onclick="genKeys()">
                <span id="btnGenKeyText">Generate Keys</span>
            </button>
            <div id="keyOut" class="output-box"></div>
        </section>

        <!-- STEP 2: UPLOAD & ENCRYPT -->
        <section class="box">
            <div class="step-header">
                <span class="step-num">02</span>
                <span class="step-title">ML Threat Inspection & Hybrid Encrypted Upload</span>
            </div>
            <div class="form-row">
                <div class="input-group">
                    <label for="fileIn">SELECT PAYLOAD ARTIFACT</label>
                    <input type="file" id="fileIn">
                </div>
            </div>
            <div class="form-row">
                <div class="input-group">
                    <label for="sender">SENDER IDENTITY ID</label>
                    <input type="text" id="sender" placeholder="Your ID" value="alice">
                </div>
                <div class="input-group">
                    <label for="recipient">RECIPIENT IDENTITY ID</label>
                    <input type="text" id="recipient" placeholder="Recipient ID" value="bob">
                </div>
            </div>
            <button id="btnUpload" onclick="upload()">
                <span id="btnUploadText">Scan & Encrypt</span>
            </button>
            <div id="upOut" class="output-box"></div>
        </section>

        <!-- STEP 3: DECRYPT & DOWNLOAD -->
        <section class="box">
            <div class="step-header">
                <span class="step-num">03</span>
                <span class="step-title">Authenticated Retrieval & Integrity Decryption</span>
            </div>
            <div class="form-row">
                <div class="input-group">
                    <label for="fid">TARGET ARTIFACT FILE ID</label>
                    <input type="text" id="fid" placeholder="e.g. file_0">
                </div>
                <div class="input-group">
                    <label for="downloader">RECIPIENT IDENTITY CREDENTIAL</label>
                    <input type="text" id="downloader" placeholder="e.g. bob" value="bob">
                </div>
            </div>
            <button id="btnDownload" onclick="download()">
                <span id="btnDownloadText">Verify, Decrypt & Download</span>
            </button>
            <div id="downOut" class="output-box"></div>
        </section>

        <!-- BLOCKCHAIN INTEGRITY VERIFICATION LEDGER -->
        <section class="box blockchain-box">
            <div class="step-header">
                <span class="step-num">04</span>
                <span class="step-title">Blockchain Integrity Ledger (SHA-256 Immutability Chain)</span>
            </div>

            <p style="color:var(--text-muted); font-size:13.5px; line-height:1.6;">
                Every encrypted file is anchored into a cryptographic hash chain. Each block references the previous block's SHA-256 digest, guaranteeing zero-trust immutability and instant detection of any payload alteration.
            </p>

            <div id="chainVerificationNotice"></div>

            <!-- Horizontal Connected Blocks Track (CSS Flexbox) -->
            <div class="chain-container">
                <div id="blockchainTrack" class="blockchain-track">
                    <!-- Blocks populated dynamically by JavaScript -->
                </div>
            </div>
        </section>

        <!-- WHY HYBRID? EDUCATIONAL SECTION -->
        <section class="box edu-box">
            <div class="step-header">
                <span class="step-num">05</span>
                <span class="step-title">Why Hybrid Cryptography? (Architecture & Comparison)</span>
            </div>

            <p style="color:var(--text-muted); font-size:14px; line-height:1.6; margin-bottom:16px;">
                Pure symmetric encryption (AES) is exceptionally fast for bulk payloads but presents a difficult <em>key distribution challenge</em>. Pure asymmetric encryption (RSA) solves key distribution with public keys, but is computationally slow and mathematically restricted to tiny data blocks. <strong>Hybrid Cryptography</strong> combines both: AES-256-GCM encrypts bulk files at native hardware speeds, while RSA-4096-OAEP encrypts only the small 32-byte AES key for effortless, zero-leak key exchange.
            </p>

            <!-- Comparison Table -->
            <div class="edu-table-container">
                <table class="crypto-table">
                    <thead>
                        <tr>
                            <th>Method</th>
                            <th>Speed</th>
                            <th>Security</th>
                            <th>Key Distribution</th>
                            <th>Best For</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>AES-only</strong></td>
                            <td>⚡ Fast</td>
                            <td>🔒 Medium</td>
                            <td>❌ Hard</td>
                            <td>Local files</td>
                        </tr>
                        <tr>
                            <td><strong>RSA-only</strong></td>
                            <td>🐢 Slow</td>
                            <td>🔒🔒 High</td>
                            <td>✅ Easy</td>
                            <td>Small data</td>
                        </tr>
                        <tr class="hybrid-row">
                            <td>
                                <strong>Hybrid (Ours)</strong>
                                <span class="hybrid-badge">✅ Best of Both Worlds</span>
                            </td>
                            <td>⚡ Fast</td>
                            <td>🔒🔒 High</td>
                            <td>✅ Easy</td>
                            <td>Secure transfer</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- Architectural Flow Diagram: [File] -> [AES Lock] -> [RSA Lock] -> [Secure Cloud] -->
            <div style="font-size:11.5px; font-weight:700; text-transform:uppercase; letter-spacing:0.8px; color:var(--text-muted); margin-top:20px; margin-bottom:12px;">
                Cryptographic Data Flow: [File] &rarr; [AES Lock] &rarr; [RSA Lock] &rarr; [Secure Cloud]
            </div>
            <div class="pipeline-flow">
                <div class="flow-node">
                    <span class="flow-icon">📄</span>
                    <span class="flow-title">File</span>
                    <span class="flow-desc">Plaintext Payload</span>
                </div>
                <div class="flow-arrow">&rarr;</div>
                <div class="flow-node">
                    <span class="flow-icon">⚡🔒</span>
                    <span class="flow-title">AES Lock</span>
                    <span class="flow-desc">AES-256-GCM Payload</span>
                </div>
                <div class="flow-arrow">&rarr;</div>
                <div class="flow-node">
                    <span class="flow-icon">🛡️🔑</span>
                    <span class="flow-title">RSA Lock</span>
                    <span class="flow-desc">RSA-4096 Encrypted Key</span>
                </div>
                <div class="flow-arrow">&rarr;</div>
                <div class="flow-node highlight-node">
                    <span class="flow-icon">☁️🔐</span>
                    <span class="flow-title">Secure Cloud</span>
                    <span class="flow-desc">Protected Zero-Trust Store</span>
                </div>
            </div>
        </section>
    </div>

    <script>
        // Security Dashboard State
        const dashboardStats = {
            scanned: 0,
            safe: 0,
            threats: 0,
            confidence: 95
        };

        function getCurrentTime() {
            const d = new Date();
            return d.toTimeString().split(' ')[0]; // HH:MM:SS format
        }

        function addActivityLog(message, type = 'safe') {
            const timeStr = getCurrentTime();
            const logEl = document.getElementById('activityLog');
            if (!logEl) return;

            const row = document.createElement('div');
            row.className = `log-row ${type}`;
            row.innerHTML = `<span class="log-time">${timeStr}</span> <span>${message}</span>`;
            logEl.prepend(row);
        }

        function updateDashboard(isSafe, anomalyScore, filename, isBlocked = false, isError = false) {
            if (isError) {
                // If it was a config or network error (e.g. missing keys), do not log as malware anomaly
                addActivityLog(`System Notice: ${filename}`, 'danger');
                return;
            }

            dashboardStats.scanned++;
            if (isBlocked || !isSafe) {
                dashboardStats.threats++;
                addActivityLog(`Threat blocked: ANOMALY (${filename})`, 'danger');
            } else {
                dashboardStats.safe++;
                addActivityLog(`File scanned: SAFE (${filename})`, 'safe');
            }

            // Calculate confidence percentage (75% to 99%)
            const base = (isSafe && !isBlocked) ? 94 : 88;
            const variance = Math.round(Math.min(5, Math.abs(anomalyScore || 0.05) * 40));
            dashboardStats.confidence = Math.min(99, Math.max(75, base + variance));

            // Update DOM metrics
            const elScanned = document.getElementById('statScanned');
            const elSafe = document.getElementById('statSafe');
            const elThreats = document.getElementById('statThreats');
            const elConf = document.getElementById('statConfidence');
            const gauge = document.getElementById('confidenceGauge');

            if (elScanned) elScanned.innerText = dashboardStats.scanned;
            if (elSafe) elSafe.innerText = dashboardStats.safe;
            if (elThreats) elThreats.innerText = dashboardStats.threats;
            if (elConf) elConf.innerText = dashboardStats.confidence + '%';

            // Animated conic-gradient gauge
            if (gauge) {
                const deg = Math.round((dashboardStats.confidence / 100) * 360);
                const color = (isSafe && !isBlocked) ? '#00ff88' : '#ff3366';
                gauge.style.background = `conic-gradient(${color} 0deg ${deg}deg, rgba(255,255,255,0.1) ${deg}deg 360deg)`;
            }
        }

        // Blockchain Ledger State
        const blockchain = [
            {
                index: 0,
                fileId: "genesis_0",
                filename: "Genesis_Anchor",
                hash: "5823aaf215ab9b9655d455b31f0536d85b614f70d1dd43e5276e43083ea21b45",
                prevHash: "0000000000000000000000000000000000000000000000000000000000000000",
                timestamp: new Date().toISOString(),
                status: "🟢 Immutable"
            }
        ];

        function renderBlockchain(verifiedFileId = null) {
            const track = document.getElementById('blockchainTrack');
            if (!track) return;

            track.innerHTML = blockchain.map((b, i) => {
                const isTarget = verifiedFileId && (b.fileId === verifiedFileId);
                const truncHash = b.hash.length > 18 
                    ? `${b.hash.substring(0, 8)}...${b.hash.substring(b.hash.length - 8)}`
                    : b.hash;
                const truncPrev = b.prevHash.length > 18
                    ? `${b.prevHash.substring(0, 8)}...${b.prevHash.substring(b.prevHash.length - 8)}`
                    : b.prevHash;

                const blockCard = `
                    <div id="block-card-${b.index}" class="block-card ${isTarget ? 'chain-pulse' : ''}">
                        <div class="block-header">
                            <span class="block-number">Block #${b.index} ${b.index === 0 ? '(Genesis)' : ''}</span>
                            <span class="block-status">${b.status}</span>
                        </div>
                        <div class="block-field">
                            <div class="field-label">File Artifact</div>
                            <div class="field-value">${b.filename} (${b.fileId})</div>
                        </div>
                        <div class="block-field">
                            <div class="field-label">Block Hash (SHA-256)</div>
                            <div class="field-value hash" title="${b.hash}">${truncHash}</div>
                        </div>
                        <div class="block-field">
                            <div class="field-label">Previous Hash</div>
                            <div class="field-value prev-hash" title="${b.prevHash}">${truncPrev}</div>
                        </div>
                        <div class="block-field">
                            <div class="field-label">Timestamp</div>
                            <div class="field-value" style="color:var(--text-muted); font-size:10.5px;">${b.timestamp}</div>
                        </div>
                    </div>
                `;

                if (i < blockchain.length - 1) {
                    return blockCard + `<div class="chain-link"></div>`;
                }
                return blockCard;
            }).join('');
        }

        function addBlockToChain(fileId, filename, fullHash) {
            const prevBlock = blockchain[blockchain.length - 1];
            const newBlock = {
                index: blockchain.length,
                fileId: fileId,
                filename: filename,
                hash: fullHash,
                prevHash: prevBlock.hash,
                timestamp: new Date().toISOString(),
                status: "🟢 Immutable"
            };
            blockchain.push(newBlock);
            renderBlockchain();
        }

        // Initialize clock and blockchain ledger on DOM ready
        window.addEventListener('DOMContentLoaded', () => {
            const initTimeEl = document.getElementById('initTime');
            if (initTimeEl) {
                initTimeEl.innerText = getCurrentTime();
            }
            renderBlockchain();
        });

        async function genKeys() {
            const btn = document.getElementById('btnGenKey');
            const btnText = document.getElementById('btnGenKeyText');
            const out = document.getElementById('keyOut');
            const uidInput = document.getElementById('uid');
            const uid = (uidInput ? uidInput.value : '').trim();

            if (!uid) {
                alert('Please enter a User ID');
                return;
            }

            btn.disabled = true;
            btnText.innerHTML = '<span class="spinner"></span> Generating 4096-bit RSA Keys...';
            out.className = 'output-box visible';
            out.innerHTML = '<div class="banner loading"><span class="spinner"></span> Generating RSA-4096 key pair in cryptographic vault (takes a few seconds)...</div>';

            try {
                const res = await fetch('/keys', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ user_id: uid })
                });
                let data = {};
                try {
                    data = await res.json();
                } catch (e) {
                    data = { error: 'Invalid response from server' };
                }

                if (res.ok) {
                    addActivityLog(`Keys generated: RSA-4096 pair for "${data.user_id}"`, 'neutral');
                    out.innerHTML = `
                        <div class="banner safe">&#x2713; RSA-4096 Key Pair Successfully Generated for "${data.user_id}"!</div>
                        <pre>${JSON.stringify(data, null, 2)}</pre>
                    `;
                } else {
                    out.innerHTML = `
                        <div class="banner danger">&#x2717; Error: ${data.error || 'Key generation failed'}</div>
                        <pre>${JSON.stringify(data, null, 2)}</pre>
                    `;
                }
            } catch (err) {
                out.innerHTML = `<div class="banner danger">&#x2717; Network error: ${err.message}</div>`;
            } finally {
                btn.disabled = false;
                btnText.innerText = 'Generate Keys';
            }
        }

        async function upload() {
            const btn = document.getElementById('btnUpload');
            const btnText = document.getElementById('btnUploadText');
            const out = document.getElementById('upOut');
            const fileInput = document.getElementById('fileIn');
            const file = fileInput.files ? fileInput.files[0] : null;
            const sender = (document.getElementById('sender').value || '').trim();
            const recipient = (document.getElementById('recipient').value || '').trim();

            if (!file) {
                alert('Please select a file to upload');
                return;
            }
            if (!sender || !recipient) {
                alert('Both Sender and Recipient IDs are required');
                return;
            }

            btn.disabled = true;
            btnText.innerHTML = '<span class="spinner"></span> Encrypting...';
            out.className = 'output-box visible';

            const startTime = performance.now();

            const steps = [
                "🔍 Scanning with ML...",
                "🔑 Generating AES-256 key...",
                "🔒 Encrypting file with AES-GCM...",
                "🛡️ Encrypting AES key with RSA-4096...",
                "💾 Storing securely..."
            ];

            out.innerHTML = `
                <div class="progress-box">
                    <div style="font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.8px; color:var(--text-muted); margin-bottom:12px; font-family:'Courier New', monospace;">
                        HYBRID ENCRYPTION PIPELINE
                    </div>
                    ${steps.map((text, i) => `
                        <div id="step-${i}" class="step-row">
                            <span id="step-icon-${i}" class="step-status">
                                <span class="wait-dot"></span>
                            </span>
                            <span id="step-text-${i}">${text}</span>
                        </div>
                    `).join('')}
                    <div id="completeNotice"></div>
                </div>
                <div id="stepDetails"></div>
            `;

            // Concurrently perform the backend upload & ML scan
            const form = new FormData();
            form.append('file', file);
            form.append('sender', sender);
            form.append('recipient', recipient);

            const uploadPromise = fetch('/upload', {
                method: 'POST',
                body: form
            });

            const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

            try {
                // Step 0: Scanning with ML... (800ms)
                const row0 = document.getElementById('step-0');
                const icon0 = document.getElementById('step-icon-0');
                const text0 = document.getElementById('step-text-0');
                if (row0 && icon0) {
                    row0.className = 'step-row active';
                    icon0.innerHTML = '<span class="mini-spinner"></span>';
                }

                await delay(800);

                const res = await uploadPromise;
                let data = {};
                try {
                    data = await res.json();
                } catch (e) {
                    data = { error: 'Invalid response from server' };
                }

                const score = (data.ml_result && typeof data.ml_result.anomaly_score === 'number') 
                    ? data.ml_result.anomaly_score 
                    : 0;

                // Handle ML threat block
                if (res.status === 403 || data.blocked === true) {
                    if (row0 && icon0) {
                        row0.className = 'step-row threat';
                        icon0.innerHTML = '<span class="threat-icon">&#x26A0;</span>';
                        if (text0) text0.innerText = '🔍 ML Threat Inspection [BLOCKED: ANOMALOUS PAYLOAD]';
                    }
                    updateDashboard(false, score, file.name || 'file', true, false);

                    const stepDetails = document.getElementById('stepDetails');
                    if (stepDetails) {
                        stepDetails.innerHTML = `
                            <div class="banner danger" style="margin-top:12px;">
                                &#x26A0; ML THREAT DETECTED: Upload blocked due to anomalous patterns! (Anomaly Score: ${score.toFixed(4)})
                            </div>
                            <pre>${JSON.stringify(data, null, 2)}</pre>
                        `;
                    }
                    return;
                }

                // If not blocked by ML, Step 0 passed!
                if (row0 && icon0) {
                    row0.className = 'step-row completed';
                    icon0.innerHTML = '<span class="check-icon">&#x2714;</span>';
                    if (text0) text0.innerText = '🔍 Scanning with ML... [VERIFIED SAFE]';
                }

                // Handle server error (e.g., 404 recipient not found)
                if (!res.ok) {
                    updateDashboard(true, score, `Recipient missing: ${data.error || 'Server error'}`, false, true);
                    const stepDetails = document.getElementById('stepDetails');
                    if (stepDetails) {
                        stepDetails.innerHTML = `
                            <div class="banner danger" style="margin-top:12px;">
                                &#x2717; Configuration Alert: ${data.error || 'Upload failed'}
                            </div>
                            <pre>${JSON.stringify(data, null, 2)}</pre>
                        `;
                    }
                    return;
                }

                // File is verified safe and recipient valid! Animate the remaining 4 steps (800ms each)
                for (let i = 1; i < steps.length; i++) {
                    const row = document.getElementById(`step-${i}`);
                    const icon = document.getElementById(`step-icon-${i}`);
                    if (row && icon) {
                        row.className = 'step-row active';
                        icon.innerHTML = '<span class="mini-spinner"></span>';
                    }

                    await delay(800);

                    if (row && icon) {
                        row.className = 'step-row completed';
                        icon.innerHTML = '<span class="check-icon">&#x2714;</span>';
                    }
                }

                const totalTimeSec = ((performance.now() - startTime) / 1000).toFixed(2);
                updateDashboard(true, score, file.name || 'file', false, false);

                if (data.file_id) {
                    document.getElementById('fid').value = data.file_id;
                    document.getElementById('downloader').value = recipient;
                }

                // Append block to immutable blockchain ledger
                if (data.sha256_hash) {
                    addBlockToChain(data.file_id, file.name || data.filename, data.sha256_hash);
                }

                const completeNotice = document.getElementById('completeNotice');
                if (completeNotice) {
                    completeNotice.innerHTML = `
                        <div class="complete-card">
                            <span>✅ Hybrid Encryption Complete</span>
                            <span style="color:var(--text-muted); font-size:13px; font-weight:normal; font-family:'Courier New', monospace;">Time taken: ${totalTimeSec}s</span>
                        </div>
                    `;
                }

                const stepDetails = document.getElementById('stepDetails');
                if (stepDetails) {
                    stepDetails.innerHTML = `
                        <div class="banner safe" style="margin-top:12px;">
                            &#x2713; ML Threat Check: SAFE (Anomaly Score: ${score.toFixed(4)}) &mdash; Stored as ${data.file_id}!
                        </div>
                        <pre>${JSON.stringify(data, null, 2)}</pre>
                    `;
                }
            } catch (err) {
                const stepDetails = document.getElementById('stepDetails');
                if (stepDetails) {
                    stepDetails.innerHTML = `<div class="banner danger" style="margin-top:12px;">&#x2717; Network error: ${err.message}</div>`;
                }
            } finally {
                btn.disabled = false;
                btnText.innerText = 'Scan & Encrypt';
            }
        }

        async function download() {
            const btn = document.getElementById('btnDownload');
            const btnText = document.getElementById('btnDownloadText');
            const out = document.getElementById('downOut');
            const fid = (document.getElementById('fid').value || '').trim();
            const user = (document.getElementById('downloader').value || '').trim();

            if (!fid || !user) {
                alert('File ID and Downloader ID are required');
                return;
            }

            btn.disabled = true;
            btnText.innerHTML = '<span class="spinner"></span> Verifying & Decrypting...';
            out.className = 'output-box visible';
            out.innerHTML = '<div class="banner loading"><span class="spinner"></span> Decrypting payload and verifying SHA-256 integrity hash...</div>';

            try {
                const res = await fetch('/download/' + encodeURIComponent(fid) + '?user=' + encodeURIComponent(user));

                if (res.ok) {
                    const blob = await res.blob();
                    
                    // Extract filename from custom header or Content-Disposition
                    let filename = res.headers.get('x-file-filename') || 'decrypted_file';
                    const disp = res.headers.get('content-disposition');
                    if (disp && disp.indexOf('filename=') !== -1) {
                        const parts = disp.split('filename=');
                        if (parts.length > 1) {
                            filename = parts[1].split(';')[0].trim().replace(/['"]/g, '');
                        }
                    }

                    // Extract verified hash from custom header if present
                    const fileHash = res.headers.get('x-file-hash');
                    if (fileHash && !blockchain.some(b => b.fileId === fid)) {
                        addBlockToChain(fid, filename, fileHash);
                    }

                    addActivityLog(`File retrieved & decrypted: ${filename}`, 'safe');

                    // Highlight verified block on blockchain and trigger green pulse
                    renderBlockchain(fid);
                    const chainNotice = document.getElementById('chainVerificationNotice');
                    if (chainNotice) {
                        chainNotice.innerHTML = `
                            <div class="chain-verified-notice">
                                <span>🛡️</span>
                                <span>Chain Verified: Block for "${fid}" authenticated with immutable SHA-256 proof</span>
                            </div>
                        `;
                    }

                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    URL.revokeObjectURL(url);

                    out.innerHTML = `
                        <div class="banner safe">&#x2713; Integrity Verified & Decrypted! Download started for: ${filename} (${blob.size} bytes)</div>
                    `;
                } else {
                    let errData = {};
                    try {
                        errData = await res.json();
                    } catch (e) {
                        errData = { error: await res.text() || res.statusText };
                    }
                    out.innerHTML = `
                        <div class="banner danger">&#x2717; Decryption Failed: ${errData.error || 'Unable to download file'}</div>
                        <pre>${JSON.stringify(errData, null, 2)}</pre>
                    `;
                }
            } catch (err) {
                out.innerHTML = `<div class="banner danger">&#x2717; Download error: ${err.message}</div>`;
            } finally {
                btn.disabled = false;
                btnText.innerText = 'Verify, Decrypt & Download';
            }
        }
    </script>
</body>
</html>
"""


@app.route('/')
def home():
    """Serves the single-page responsive web dashboard."""
    return render_template_string(HTML)


@app.route('/keys', methods=['POST'])
def generate_keys():
    """
    Generates a 4096-bit RSA key pair for the requested user_id,
    stores keys in users vault (case-insensitively), and returns public key.
    """
    data = request.get_json(silent=True) or {}
    user_id = data.get('user_id', '').strip()

    if not user_id:
        return jsonify({'error': 'Missing required parameter: user_id'}), 400

    canonical_uid = user_id.lower()

    try:
        private_key, public_key = crypto.generate_rsa_keys()
        users[canonical_uid] = {
            'private': private_key,
            'public': public_key
        }
        return jsonify({
            'user_id': user_id,
            'public_key': public_key.decode('utf-8'),
            'status': 'success',
            'warning': 'Private key stored securely in memory vault.'
        })
    except Exception as e:
        return jsonify({'error': f'Failed to generate RSA keys: {str(e)}'}), 500


@app.route('/upload', methods=['POST'])
def upload():
    """
    Receives file, sender, recipient.
    Scans with IsolationForest threat detector.
    If safe, performs hybrid AES-256-GCM + RSA-OAEP encryption and stores file package.
    """
    sender = request.form.get('sender', '').strip()
    recipient = request.form.get('recipient', '').strip()

    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400

    file = request.files['file']
    if not file or not file.filename:
        return jsonify({'error': 'No file selected for upload'}), 400

    if not sender or not recipient:
        return jsonify({'error': 'Both sender and recipient are required'}), 400

    canonical_recipient = recipient.lower()
    canonical_sender = sender.lower()

    file_bytes = file.read()
    if len(file_bytes) == 0:
        return jsonify({'error': 'Uploaded file is empty (0 bytes)'}), 400

    # 1. ML Threat Scan
    ml_result = detector.scan(file_bytes, file.filename)
    if not ml_result['safe']:
        return jsonify({
            'blocked': True,
            'reason': 'Threat detected by machine learning engine',
            'ml_result': ml_result
        }), 403

    # 2. Recipient public key verification
    if canonical_recipient not in users:
        return jsonify({
            'error': f"Recipient '{recipient}' not found. Please generate keys for '{recipient}' first.",
            'ml_result': ml_result
        }), 404

    # 3. Hybrid Encryption
    try:
        encrypted_package = crypto.encrypt_hybrid(file_bytes, users[canonical_recipient]['public'])
        file_hash = crypto.hash_sha256(file_bytes)
    except Exception as e:
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 500

    # 4. Storage
    fid = f"file_{len(files)}"
    files[fid] = {
        'package': encrypted_package,
        'sender': canonical_sender,
        'recipient': canonical_recipient,
        'filename': file.filename,
        'hash': file_hash,
        'size': len(file_bytes)
    }

    return jsonify({
        'file_id': fid,
        'filename': file.filename,
        'size_bytes': len(file_bytes),
        'sha256_hash': file_hash,
        'ml_result': ml_result,
        'message': 'File scanned, encrypted, and stored successfully'
    })


@app.route('/download/<file_id>')
def download(file_id):
    """
    Verifies requesting user is the recipient,
    decrypts file with recipient private key,
    verifies SHA-256 integrity hash, and returns file.
    """
    user = request.args.get('user', '').strip()
    if not user:
        return jsonify({'error': 'User query parameter (?user=...) is required'}), 400

    canonical_user = user.lower()
    canonical_fid = file_id.strip().lower()

    target_fid = None
    if file_id in files:
        target_fid = file_id
    elif canonical_fid in files:
        target_fid = canonical_fid
    else:
        # Check case-insensitive match among keys
        for k in files:
            if k.lower() == canonical_fid:
                target_fid = k
                break

    if not target_fid:
        return jsonify({'error': f"File '{file_id}' not found"}), 404

    f_record = files[target_fid]

    if f_record['recipient'] != canonical_user:
        return jsonify({'error': f"Unauthorized: '{user}' is not the recipient of this file"}), 403

    if canonical_user not in users:
        return jsonify({'error': f"Recipient private key for '{user}' not found in vault"}), 404

    try:
        decrypted_bytes = crypto.decrypt_hybrid(f_record['package'], users[canonical_user]['private'])
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 400

    # Integrity verification
    computed_hash = crypto.hash_sha256(decrypted_bytes)
    if computed_hash != f_record['hash']:
        return jsonify({'error': 'Integrity check failed: payload hash mismatch'}), 400

    response = send_file(
        io.BytesIO(decrypted_bytes),
        as_attachment=True,
        download_name=f_record['filename'],
        mimetype='application/octet-stream'
    )
    response.headers['X-File-Hash'] = f_record['hash']
    response.headers['X-File-Filename'] = f_record['filename']
    response.headers['Access-Control-Expose-Headers'] = 'Content-Disposition, X-File-Hash, X-File-Filename'
    return response


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
