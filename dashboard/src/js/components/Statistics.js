import React from 'react';
import moment from 'moment';
import {Pie, Line} from 'react-chartjs-2';
import {SEVERITY_ENUM, SEVERITY_COLORS} from '../enums';
import {stringToColour} from '../utils';

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

    let typeData = this.props.events.reduce((accumulator, currentValue) => {
      if (!accumulator[currentValue['trail_type']]) {
        accumulator[currentValue['trail_type']] = 0;
      }
      accumulator[currentValue['trail_type']]++;
      return accumulator;
    }, {});

    let avgAccuracy = Math.round((this.props.events.reduce((accumulator, currentValue) => accumulator + currentValue.accuracy, 0) / this.props.events.length) * 100) || 100;
    
    return <div style={{
      display: 'flex',
      justifyContent: 'space-between'
    }}>
        <div style={{
          width: '200px',
          height: '200px'
        }}>
          <Pie 
            data={{
              labels: Object.keys(severityData).map(key => SEVERITY_ENUM[key]),
              datasets: [{
                data: Object.values(severityData),
                backgroundColor: Object.keys(severityData).map(key => SEVERITY_COLORS[key]),
                hoverBackgroundColor: Object.keys(severityData).map(key => SEVERITY_COLORS[key])
              }]
            }}
            width={200}
            height={200}
            options={{
              responsive: true,
              maintainAspectRatio: false
            }}
            style={{display: 'inline-block', width: '200px'}} />
        </div>
        <div style={{
          width: '200px',
          height: '200px'
        }}>
          <Pie 
            data={{
              labels: Object.keys(typeData),
              datasets: [{
                data: Object.values(typeData),
                backgroundColor: Object.keys(severityData).map(key => stringToColour(key)),
                hoverBackgroundColor: Object.keys(severityData).map(key => stringToColour(key))
              }]
            }}
            width={200}
            height={200}
            options={{
              responsive: true,
              maintainAspectRatio: false
            }}
            style={{display: 'inline-block', width: '200px'}} />
        </div>
        <div style={{
          textAlign: 'center',
          fontSize: '1.4rem',
          width: '200px',
          height: '200px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          <p>Average accuracy {avgAccuracy}%</p>
        </div>
      </div>
  }

  renderFrequency() {
    let freqData = this.props.events.reduce((accumulator, currentValue) => {
      let date = moment(new Date(currentValue['packet_sec'] * 1000)).format("YYYY-MM-DD");
      if (!accumulator[date]) {
        accumulator[date] = 0;
      }
      accumulator[date]++;
      return accumulator;
    }, {});
    
    return <div>
        <Line 
          data={{
            labels: Object.keys(freqData),
            datasets: [
              {
                label: 'Frequency',
                fill: false,
                lineTension: 0.1,
                backgroundColor: 'rgba(75,192,192,0.4)',
                borderColor: 'rgba(75,192,192,1)',
                borderCapStyle: 'butt',
                borderDash: [],
                borderDashOffset: 0.0,
                borderJoinStyle: 'miter',
                pointBorderColor: 'rgba(75,192,192,1)',
                pointBackgroundColor: '#fff',
                pointBorderWidth: 1,
                pointHoverRadius: 5,
                pointHoverBackgroundColor: 'rgba(75,192,192,1)',
                pointHoverBorderColor: 'rgba(220,220,220,1)',
                pointHoverBorderWidth: 2,
                pointRadius: 1,
                pointHitRadius: 10,
                data: Object.values(freqData)
              }
            ]
          }}
          width={200}
          height={200}
          options={{
            responsive: true,
            maintainAspectRatio: false
          }}
          style={{display: 'inline-block', width: '200px'}} />
      </div>
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

      <div style={{
        padding: '20px'
      }}>
        {this.state.selectedTab === 'severity' ? this.renderSeverity() : this.renderFrequency()}
      </div>
    </div>;
  }
}