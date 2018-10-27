import React from 'react';

export default class Packets extends React.Component {
  render() {
    return <div>
      {JSON.stringify(this.props.trail.packets)}
    </div>;
  }
}