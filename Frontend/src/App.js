import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import HomePage from './pages/HomePage';
import LearnMorePage from './pages/LearnMorePage';
import LoginPage from './pages/LoginPage';
import AdminDash from './pages/admindashboard_page';
import AdminRegisterUser from './pages/Adminregisteruser';
import ManageUsers from './pages/ManageUsers';

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
      </Routes>
    </Router>
  );
};

export default App;
