import React, { useEffect } from "react";
import PropTypes from "prop-types";

export default function WebpageButton({text, onClick}){
    return(
        <button 
            onClick={onClick}
            style={{
                padding: '10px 20px',
                backgroundColor: '#007BFF',
                color: '#FFFFFF',
                border: 'none',
                borderRadius: '5px',
                cursor: 'pointer'}}
        >
            {text}
        </button>
    );      
}