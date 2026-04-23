import './ReportsSection.css';

function ReportsSection() {
  return (
    <div className="reports-section-content">
      <div className="reports-header-main">
        <h1>Security Reports</h1>
        <p>View and download all your vulnerability scan results</p>
      </div>

      <div className="reports-stats-grid">
        <div className="report-stat-box">
          <div className="stat-info-box">
            <p className="stat-label-box">Total Reports</p>
            <h3 className="stat-value-box">247</h3>
            <span className="stat-desc-box">Generated reports</span>
          </div>
        </div>
        <div className="report-stat-box">
          <div className="stat-info-box">
            <p className="stat-label-box">New Vulnerabilities</p>
            <h3 className="stat-value-box">32</h3>
            <span className="stat-desc-box">Requires attention</span>
          </div>
        </div>
        <div className="report-stat-box">
          <div className="stat-info-box">
            <p className="stat-label-box">Critical Issues</p>
            <h3 className="stat-value-box">7</h3>
            <span className="stat-desc-box">Immediate action required</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ReportsSection;
