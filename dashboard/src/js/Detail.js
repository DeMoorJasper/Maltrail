import React from 'react';

import Packets from './components/Packets';

export default class Detail extends React.Component {
  render() {
    return <main>
      <h1>Details of {this.props.selectedTrail.info}</h1>
      <ul>
        <li>{this.props.selectedTrail.src_ip} -> {this.props.selectedTrail.dst_ip}</li>
        <li>Sensor: {this.props.selectedTrail.sensor_name}</li>
        <li>Trail: {this.props.selectedTrail.trail}</li>
        <li>Type: {this.props.selectedTrail.trail_type}</li>
        <li>Severity: {this.props.selectedTrail.severity}</li>
      </ul>
      <h2>Packets</h2>
      <Packets trail={this.props.selectedTrail} />
    </main>;
  }
}