import React, { useState } from 'react';
import {useNavigate} from 'react-router-dom';
import './HomePage.css';
import '../../styles/webpage.css';
import '../../App.css'

const HomePage = () => {

    const navigate = useNavigate();
    const DbLockImage = '/assets/images/DbLockImage.png';
    const RanScanLogo = '/assets/images/RanScanLogo.png';
    const ProactiveIcon = '/assets/images/ProactiveIcon.png';
    const rocketIcon = '/assets/images/rocketIcon.png';
    const realTimeResposeIcon = '/assets/images/realTimeResponseIcon.png';
    
    return (
        <div className="home-container">
            {/* Header */}
            <div className="header">
                <div className="header-left">
                    <img src={RanScanLogo} alt="RanScanLogo" className="logo" />
                    <h1>
                        <span className="title-red">Ran</span>
                        <span className="title-grey">ScanAI</span>
                    </h1>
                </div>
            </div>

            {/* Hero Section */}
            <section className="hero-box">
                <div className="hero-top">
                    <div className="hero-text">
                        <h2>AI-Driven Ransomware Detection System</h2>
                        <p>
                            Leveraging the power of artificial intelligence to monitor and <br />
                            identify potential ransomware threats in real time.
                        </p>
                        <button className="orange-button"
                        onClick={() => navigate('/learn-more')}>
                            LEARN MORE
                        </button>
                    </div>
                    <div>
                        <img src={DbLockImage} alt="DbLockImage" className="Db-image"/> 
                    </div>
                </div>

                <div className="feature-section">
                    <div className="feature-pane">
                        <img src={ProactiveIcon} alt="ProactiveIcon" className="feature-icon"/>
                        <h3>Proactive Defence</h3>
                        <p>Preemptive measures to fortify your network and mitigate ransomware risks before they escalate</p>
                    </div>

                    <div className="feature-pane">
                        <img src={rocketIcon} alt="Rocket Icon" className="feature-icon"/>
                        <h3>Rapid Deployment</h3>
                        <p>Quick and seamless integration to provide immediate protection against emerging threats</p>
                    </div>

                    <div className="feature-pane">
                        <img src={realTimeResposeIcon} alt="Real Time Response Icon" className="feature-icon"/>
                        <h3>Real-Time Response</h3>
                        <p>Instantaneous detection and mitigation to minimize the impact of ransomware on your operations</p>
                    </div>
                </div>

                <button 
                    className="login-button" 
                    onClick={() => navigate('/login')}
                    style={{ marginTop: "20px" }}
                >
                Login
                </button>
            </section>

        <section className="contact-container" style={{marginTop:"20px"}}>
            <h2> Contact Us:</h2>
            <div className="contact-flex">
            <div className="contact-column">
                <p><strong>Security Team</strong><br />security@ranscanai.com</p>
                <p><strong>System Support Team</strong><br />support@ranscanai.com</p>
                <p><strong>Business Location</strong><br />No19, Suria KLCC, Kuala Lumpur, Malaysia</p>
            </div>
            <div className="contact-column">
                <p><strong>Sales Team</strong><br />sales@ranscanai.com</p>
                <p><strong>Emergency Hotline</strong><br />+(60) 123213457</p>
            </div>
            </div>

        </section>

        <div className="hero-footer">
            <p className="courierPrime-font" style={{ fontSize: "12px" }}>
            &copy; 2024 RanScanAI. All rights reserved.
            </p>
        </div>
        </div>
    );
};

export default HomePage;