import React from 'react';

import { DateRangePicker } from 'react-dates';

export default class Filters extends React.Component {
  constructor(props) {
    super(props);

    this.state = {
      startDate: null,
      endDate: null,
      focusedInput: null
    };
  }

  render() {
    return <div className="filters">
      <DateRangePicker
        startDate={this.state.startDate}
        startDateId="your_unique_start_date_id"
        endDate={this.state.endDate}
        endDateId="your_unique_end_date_id"
        onDatesChange={
          ({ startDate, endDate }) => this.setState({ startDate, endDate })
        }
        focusedInput={this.state.focusedInput}
        onFocusChange={
          focusedInput => this.setState({ focusedInput })
        }
      />
      <input placeholder="Search..." className="search-input" />
    </div>;
  }
}