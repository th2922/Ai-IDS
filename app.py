"""
AI-Based Network Intrusion Detection System (IDS)
A Streamlit demo for hackathon presentation
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from sklearn.ensemble import IsolationForest
import time
from datetime import datetime

# Page configuration
st.set_page_config(
    page_title="AI-Based IDS",
    page_icon="🛡️",
    layout="wide"
)

# Initialize session state variables
if 'traffic_data' not in st.session_state:
    st.session_state.traffic_data = []
if 'detection_log' not in st.session_state:
    st.session_state.detection_log = []
if 'simulation_running' not in st.session_state:
    st.session_state.simulation_running = False
if 'simulation_mode' not in st.session_state:
    st.session_state.simulation_mode = None
if 'model_trained' not in st.session_state:
    st.session_state.model_trained = False
if 'model' not in st.session_state:
    st.session_state.model = None

# Function to train the IsolationForest model on normal traffic
def train_model():
    """Train IsolationForest on synthetic normal traffic patterns"""
    np.random.seed(42)
    
    # Generate normal traffic training data
    normal_samples = 200
    normal_packet_rate = np.random.normal(50, 10, normal_samples)  # Mean=50, std=10
    normal_pkt_size = np.random.normal(500, 50, normal_samples)    # Mean=500, std=50
    normal_unique_ips = np.random.normal(5, 2, normal_samples)     # Mean=5, std=2
    
    # Create training dataframe
    training_data = pd.DataFrame({
        'packet_rate': normal_packet_rate,
        'avg_pkt_size': normal_pkt_size,
        'unique_dest_ips': normal_unique_ips
    })
    
    # Train IsolationForest
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(training_data)
    
    return model

# Function to generate synthetic traffic data
def generate_traffic(mode='normal'):
    """Generate synthetic network traffic metrics"""
    if mode == 'normal':
        # Normal traffic: stable patterns
        packet_rate = np.random.normal(50, 10)
        avg_pkt_size = np.random.normal(500, 50)
        unique_dest_ips = np.random.normal(5, 2)
    else:  # attack mode
        # Attack traffic: sudden spikes and anomalies
        packet_rate = np.random.normal(150, 40)  # Higher rate
        avg_pkt_size = np.random.normal(800, 200)  # Larger packets
        unique_dest_ips = np.random.normal(25, 10)  # Many unique IPs
    
    # Ensure positive values
    packet_rate = max(0, packet_rate)
    avg_pkt_size = max(0, avg_pkt_size)
    unique_dest_ips = max(1, int(unique_dest_ips))
    
    return {
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'packet_rate': packet_rate,
        'avg_pkt_size': avg_pkt_size,
        'unique_dest_ips': unique_dest_ips
    }

# Function to detect intrusion using the trained model
def detect_intrusion(data_point, model):
    """Use IsolationForest to detect anomalies"""
    features = pd.DataFrame([{
        'packet_rate': data_point['packet_rate'],
        'avg_pkt_size': data_point['avg_pkt_size'],
        'unique_dest_ips': data_point['unique_dest_ips']
    }])
    
    # Predict: 1 = normal, -1 = anomaly
    prediction = model.predict(features)[0]
    return prediction

# Header
st.title("🛡️ AI-Based Network Intrusion Detection System (IDS)")
st.markdown("**Real-time anomaly detection using Machine Learning**")

# Sidebar controls
st.sidebar.header("🎮 Control Panel")
st.sidebar.markdown("---")

# Train model button (only needs to be done once)
if not st.session_state.model_trained:
    if st.sidebar.button("🧠 Initialize AI Model", type="primary"):
        with st.spinner("Training IsolationForest model..."):
            st.session_state.model = train_model()
            st.session_state.model_trained = True
            st.sidebar.success("✅ Model trained successfully!")
            time.sleep(1)
            st.rerun()

if st.session_state.model_trained:
    st.sidebar.success("✅ AI Model Ready")
    
    # Simulation controls
    st.sidebar.markdown("### Simulation Controls")
    
    col1, col2 = st.sidebar.columns(2)
    
    with col1:
        if st.button("▶️ Normal Traffic", disabled=st.session_state.simulation_running):
            st.session_state.simulation_running = True
            st.session_state.simulation_mode = 'normal'
            st.rerun()
    
    with col2:
        if st.button("⚠️ Attack Mode", disabled=st.session_state.simulation_running):
            st.session_state.simulation_running = True
            st.session_state.simulation_mode = 'attack'
            st.rerun()
    
    if st.sidebar.button("⏹️ Stop Simulation"):
        st.session_state.simulation_running = False
        st.rerun()
    
    if st.sidebar.button("🔄 Reset All Data"):
        st.session_state.traffic_data = []
        st.session_state.detection_log = []
        st.session_state.simulation_running = False
        st.session_state.simulation_mode = None
        st.rerun()
    
    # Detection Log
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📋 Recent Detections (Last 5)")
    if st.session_state.detection_log:
        for log in st.session_state.detection_log[-5:][::-1]:
            if log['status'] == 'intrusion':
                st.sidebar.error(f"🚨 {log['time']} - INTRUSION")
            else:
                st.sidebar.success(f"✅ {log['time']} - Normal")
    else:
        st.sidebar.info("No detections yet")

else:
    st.sidebar.warning("⚠️ Please initialize the AI model first")

# Main content area
if st.session_state.model_trained:
    # Create three columns for metrics
    col1, col2, col3 = st.columns(3)
    
    metric1 = col1.empty()
    metric2 = col2.empty()
    metric3 = col3.empty()
    
    # Status indicator
    status_container = st.empty()
    
    # Chart placeholder
    chart_placeholder = st.empty()
    
    # Simulation loop
    if st.session_state.simulation_running and st.session_state.simulation_mode:
        for i in range(30):  # Run for 30 iterations
            if not st.session_state.simulation_running:
                break
            
            # Generate traffic data
            traffic_point = generate_traffic(st.session_state.simulation_mode)
            
            # Detect intrusion
            prediction = detect_intrusion(traffic_point, st.session_state.model)
            
            # Add to traffic data
            st.session_state.traffic_data.append({
                **traffic_point,
                'status': 'normal' if prediction == 1 else 'intrusion'
            })
            
            # Keep only last 50 data points for display
            if len(st.session_state.traffic_data) > 50:
                st.session_state.traffic_data.pop(0)
            
            # Add to detection log
            st.session_state.detection_log.append({
                'time': traffic_point['timestamp'],
                'status': 'normal' if prediction == 1 else 'intrusion'
            })
            
            # Update metrics
            latest = st.session_state.traffic_data[-1]
            metric1.metric(
                "📊 Packet Rate",
                f"{latest['packet_rate']:.1f} pkt/s",
                delta=None
            )
            metric2.metric(
                "📦 Avg Packet Size",
                f"{latest['avg_pkt_size']:.0f} bytes",
                delta=None
            )
            metric3.metric(
                "🌐 Unique IPs",
                f"{latest['unique_dest_ips']:.0f}",
                delta=None
            )
            
            # Update status indicator
            if prediction == -1:
                status_container.error("### 🚨 INTRUSION DETECTED!")
            else:
                status_container.success("### ✅ Normal Traffic")
            
            # Update chart
            df = pd.DataFrame(st.session_state.traffic_data)
            
            fig = go.Figure()
            
            # Add packet rate line
            colors = ['red' if x == 'intrusion' else 'green' for x in df['status']]
            fig.add_trace(go.Scatter(
                y=df['packet_rate'],
                mode='lines+markers',
                name='Packet Rate',
                line=dict(color='blue', width=2),
                marker=dict(size=8, color=colors)
            ))
            
            fig.update_layout(
                title='Real-Time Network Traffic Monitor',
                xaxis_title='Time',
                yaxis_title='Packet Rate (pkt/s)',
                height=400,
                hovermode='x unified',
                showlegend=True
            )
            
            chart_placeholder.plotly_chart(fig, use_container_width=True)
            
            time.sleep(1)  # Update every second
        
        # Stop simulation after 30 iterations
        st.session_state.simulation_running = False
        st.rerun()
    
    else:
        # Display current state without simulation
        if st.session_state.traffic_data:
            df = pd.DataFrame(st.session_state.traffic_data)
            
            latest = st.session_state.traffic_data[-1]
            metric1.metric("📊 Packet Rate", f"{latest['packet_rate']:.1f} pkt/s")
            metric2.metric("📦 Avg Packet Size", f"{latest['avg_pkt_size']:.0f} bytes")
            metric3.metric("🌐 Unique IPs", f"{latest['unique_dest_ips']:.0f}")
            
            if latest['status'] == 'intrusion':
                status_container.error("### 🚨 INTRUSION DETECTED!")
            else:
                status_container.success("### ✅ Normal Traffic")
            
            # Display chart
            fig = go.Figure()
            colors = ['red' if x == 'intrusion' else 'green' for x in df['status']]
            fig.add_trace(go.Scatter(
                y=df['packet_rate'],
                mode='lines+markers',
                name='Packet Rate',
                line=dict(color='blue', width=2),
                marker=dict(size=8, color=colors)
            ))
            
            fig.update_layout(
                title='Network Traffic History',
                xaxis_title='Time',
                yaxis_title='Packet Rate (pkt/s)',
                height=400,
                hovermode='x unified'
            )
            
            chart_placeholder.plotly_chart(fig, use_container_width=True)
        else:
            st.info("👆 Click a simulation button in the sidebar to start monitoring traffic!")
            
            # Show example chart
            st.markdown("### How It Works")
            st.markdown("""
            1. **Initialize AI Model**: Train the IsolationForest algorithm on normal traffic patterns
            2. **Normal Traffic**: Generates stable, low-rate traffic (green indicators)
            3. **Attack Simulation**: Creates sudden spikes and anomalies (red alerts)
            4. **Real-time Detection**: The AI model analyzes each data point and flags anomalies
            """)

else:
    st.info("👈 Click 'Initialize AI Model' in the sidebar to begin!")
    st.markdown("### About This System")
    st.markdown("""
    This **AI-Based Intrusion Detection System** uses machine learning to identify network anomalies:
    
    - **Algorithm**: IsolationForest (unsupervised anomaly detection)
    - **Features**: Packet rate, packet size, unique destination IPs
    - **Training**: Pre-trained on synthetic normal traffic patterns
    - **Detection**: Real-time classification of traffic as normal or intrusion
    """)

# Footer
st.markdown("---")
st.markdown("**🎓 Hackathon Demo** | Built with Streamlit + scikit-learn | AI-Powered Security")