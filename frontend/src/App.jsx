// App.jsx - Main app with routing
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import AdvancedDashboard from './components/AdvancedDashboard';
import ConfigPanel from './components/ConfigPanel';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<AdvancedDashboard />} />
        <Route path="/config" element={<ConfigPanel />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
}

export default App;