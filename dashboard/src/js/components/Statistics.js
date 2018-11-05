import React from 'react';
import {Pie} from 'react-chartjs-2';
import {SEVERITY_ENUM, SEVERITY_COLORS} from '../enums';

export default class Statistics extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      selectedTab: "severity"
    };

    this.renderSeverity = this.renderSeverity.bind(this);
    this.renderSeverity = this.renderSeverity.bind(this);
  }

  renderSeverity() {
    let severityData = this.props.events.reduce((accumulator, currentValue) => {
      if (!accumulator[currentValue['severity']]) {
        accumulator[currentValue['severity']] = 0;
      }
      accumulator[currentValue['severity']]++;
      return accumulator;
    }, {});
    
    return <div>
        <Pie 
          data={{
            labels: Object.keys(severityData).map(key => SEVERITY_ENUM[key]),
            datasets: [{
              data: Object.values(severityData),
              backgroundColor: Object.keys(severityData).map(key => SEVERITY_COLORS[key]),
              hoverBackgroundColor: Object.keys(severityData).map(key => SEVERITY_COLORS[key])
            }]
          }} />
      </div>
  }

  renderFrequency() {
    return <div>Frequency</div>;
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

      {this.state.selectedTab === 'severity' ? this.renderSeverity() : this.renderFrequency()}
    </div>;
  }
}