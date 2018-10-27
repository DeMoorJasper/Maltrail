import React from 'react';

import Filters from './components/Filters';
import Statistics from './components/Statistics';
import Trails from './components/Trails';

export default class Home extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      trails: []
    }
  }

  componentDidUpdate(prevProps) {
    if (prevProps.events !== this.props.events) {
      this.updateTrails();
    }
  }

  updateTrails() {
    let trails = [];
    if (Array.isArray(this.props.events)) {
      trails = this.props.events.reduce((accumulator, currentValue) => {
        let key = `${currentValue.trail_type}-${currentValue.src_ip}-${currentValue.dst_ip}-${currentValue.trail}`;

        if (!accumulator[key]) {
          accumulator[key] = {
            sensor_name: currentValue.sensor_name,
            info: currentValue.info,
            trail: currentValue.trail,
            trail_type: currentValue.trail_type,
            severity: currentValue.severity,
            src_ip: currentValue.src_ip,
            dst_ip: currentValue.dst_ip,
            packets: []
          }
        }

        accumulator[key].packets.push({
          src_port: currentValue.src_port,
          dst_port: currentValue.dst_port,
          packet_data: currentValue.packet_data,
          packet_sec: currentValue.packet_sec,
          packet_usec: currentValue.packet_usec,
          reference: currentValue.reference
        });

        return accumulator;
      }, {})
    }
    
    this.setState({trails});
  }

  render() {
    const {
      trails
    } = this.state;

    return <div>
      <Statistics />
      <Filters />
      <Trails trails={trails} setSelectedTrail={this.props.setSelectedTrail} />
    </div>;
  }
}