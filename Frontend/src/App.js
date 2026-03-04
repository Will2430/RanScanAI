import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import HomePage from './pages/HomePage';
import LearnMorePage from './pages/LearnMorePage';
import LoginPage from './pages/LoginPage';
import AdminDash from './pages/admindashboard_page';
import AdminRegisterUser from './pages/Adminregisteruser';
import ManageUsers from './pages/ManageUsers';
import UncertainSampleDetail from './pages/UncertainSampleDetail';
import SummaryReportPage from './pages/SummaryReportPage';
import ViewAllDetectionDetails from './pages/viewalldetectiondetails_page';

const App = () => {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/learn-more" element={<LearnMorePage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/admin-dashboard" element={<AdminDash />} />
        <Route path="/admin-register-user" element={<AdminRegisterUser />} />
        <Route path="/admin-manage-users" element={<ManageUsers />} />
        <Route path="/admin/uncertain-sample/:detectionId" element={<UncertainSampleDetail />} />
        <Route path="/admin/summary-report/:month" element={<SummaryReportPage />} />
        <Route path="/detection/:detectionId" element={<ViewAllDetectionDetails />} />
      </Routes>
    </Router>
  );
};

export default App;
