import React from 'react';
import { Link } from 'react-router-dom';


const Navigation = () => {
  return (
      <div>
        <Link to="/" className="nav-logo">
        </Link>
        <ul className="nav-menu">
          <li className="nav-item">
            <Link to="/" className="nav-link">
            </Link>
          </li>
          <li className="nav-item">
            <Link to="/learn-more" className="nav-link">
            </Link>
          </li>
        </ul>
      </div>
  );
};

export default Navigation;