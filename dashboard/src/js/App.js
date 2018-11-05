import React from 'react';
import request from 'request-promise-native';

import Home from './Home';
import Detail from './Detail';
import {API_SERVER, UPDATE_INTERVAL} from '../../config.json';

export default class App extends React.Component {
  constructor(props) {
    super(props);

    this.state = {
      selectedTrail: null,
      events: [],
      startDate: null,
      endDate: null
    }

    this.setSelectedTrail = this.setSelectedTrail.bind(this);
  }

  async updateEvents() {
    let events = await this.fetchEvents(this.state.startDate || new Date(), this.state.endDate);
    this.setState({events});
  }

  async componentDidMount() {
    await this.updateEvents();
    
    this.updateInterval = window.setInterval(() => {
      if (this.state.startDate || this.state.endDate) {
        return;
      }

      this.updateEvents();
    }, UPDATE_INTERVAL);
  }

  componentWillUnmount() {
    if (this.updateInterval) {
      window.clearInterval(this.updateInterval);
    }
  }

  setSelectedTrail(trail) {
    this.setState({
      selectedTrail: trail
    });
  }

  async fetchEvents(startDate = new Date(), endDate) {
    console.log('Fetching events:', startDate, endDate);
    
    return JSON.parse(await request(API_SERVER + '/events'));
  }

  render() {
    const {
      selectedTrail
    } = this.state;
    
    return <main>
      <h1>Maltrail Dashboard</h1>
      {
        selectedTrail
          ? <Detail selectedTrail={selectedTrail} setSelectedTrail={this.setSelectedTrail} />
          : <Home events={this.state.events} setSelectedTrail={this.setSelectedTrail} />
      }
    </main>;
  }
}