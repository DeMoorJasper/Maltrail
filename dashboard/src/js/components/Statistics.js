import React from 'react';

export default class Statistics extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      selectedTab: "severity"
    };
  }

  render() {
    return <div className="statistics">
      <button 
        className={`statistics-button ${this.state.selectedTab === 'severity' ? "statistics-button-selected" : ''}`}
        onClick={() => {
          this.setState({
            selectedTab: "severity"
          })
        }}>
        Severity
      </button>
      <button 
        className={`statistics-button ${this.state.selectedTab === 'frequency' ? "statistics-button-selected" : ''}`}
        onClick={() => {
          this.setState({
            selectedTab: "frequency"
          })
        }}>
        Frequency
      </button>
      
      <div style={{height: '200px'}}></div>
    </div>;
  }
}