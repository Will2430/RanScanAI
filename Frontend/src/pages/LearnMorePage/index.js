import React, { useState } from 'react';
import './LearnMorePage.css';
import '../../styles/webpage.css';
import '../../App.css';

const LearnMorePage = () => {
    const RanScanLogo = '/assets/images/RanScanLogo.png';
    
    return (
        <div className="home-container">      
            <div className="header">
                <div className="header-left">
                    <img src={RanScanLogo} alt="RanScanLogo" className="logo" />
                    <h1>
                        <span className="title-red">Ran</span>
                        <span className="title-grey">ScanAI</span>
                    </h1>
                </div>
            </div>

            {/* Main Content Section */}
            <section className="learn-more-container">
                <h2>Learn More About RanScanAI</h2>
                <p>
                    RanScanAI is an advanced AI-driven ransomware detection and prevention system 
                    designed to protect your organization from evolving cyber threats.
                </p>

                <div className="features-grid">
                    <div className="feature-box">
                        <h3>Advanced Detection</h3>
                        <p>Our AI algorithms detect suspicious patterns and behaviors before ransomware can execute.</p>
                    </div>
                    <div className="feature-box">
                        <h3>Real-Time Protection</h3>
                        <p>Continuous monitoring ensures your systems are protected 24/7 from emerging threats.</p>
                    </div>
                    <div className="feature-box">
                        <h3>Easy Integration</h3>
                        <p>Seamlessly integrate with your existing infrastructure with minimal disruption.</p>
                    </div>
                </div>
            </section>

            <footer className="hero-footer">
                <p>&copy; 2024 RanScanAI. All rights reserved.</p>
            </footer>
        </div>
    );
}; 

export default LearnMorePage;