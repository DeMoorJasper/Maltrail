import React from 'react';

import Packets from './components/Packets';

export default class Detail extends React.Component {
  constructor(props) {
    super(props);

    this.state = {
      selectedPacket: null
    }

    this.setSelectedPacket = this.setSelectedPacket.bind(this);
  }

  setSelectedPacket(selectedPacket) {
    console.log(selectedPacket);
    this.setState({
      selectedPacket
    });
  }

  renderPacketDetails() {
    const {selectedPacket} = this.state;

    return <div>
      <h2>Selected Packet Details</h2>

      <ul className="detail-list">
        <li>Timestamp: {selectedPacket.timestamp}</li>
        <li>Source: {selectedPacket.src_ip}:{selectedPacket.src_port}</li>
        <li>Destination: {selectedPacket.dst_ip}:{selectedPacket.dst_port}</li>
        <li>Trail: {selectedPacket.trail}</li>
        <li>Reference: {selectedPacket.reference}</li>
        <li>Packet data:</li>
        <li><textarea className="packet-data" value={selectedPacket.packet_data} disabled /></li>
      </ul>
    </div>;
  }

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

      {this.state.selectedPacket && this.renderPacketDetails()}
      
      <Packets trail={this.props.selectedTrail} setSelectedPacket={this.setSelectedPacket} />
    </div>;
  }
}
