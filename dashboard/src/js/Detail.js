import React from 'react';

import Packets from './components/Packets';

export default class Detail extends React.Component {
  render() {
    return <div>
      <a onClick={
        () => this.props.setSelectedTrail(null)
      } className="back">Go back</a>

      <h2>Details of {this.props.selectedTrail.info}</h2>
      
      <ul className="detail-list">
        <li>{this.props.selectedTrail.src_ip} -> {this.props.selectedTrail.dst_ip}</li>
        <li>Sensor: {this.props.selectedTrail.sensor_name}</li>
        <li>Type: {this.props.selectedTrail.trail_type}</li>
        <li>Severity: {this.props.selectedTrail.severity}</li>
      </ul>
      
      <Packets trail={this.props.selectedTrail} />
    </div>;
  }
}