import React from 'react';

import { defaultTableRowRenderer as DefaultTableRowRenderer, Column, Table, AutoSizer, SortDirection } from 'react-virtualized';
import moment from 'moment';

function rowRendererFactory(setSelectedTrail, trails) {
  return (props) => {
    return <DefaultTableRowRenderer {...props} onRowClick={({rowData}) => {
      console.log(rowData);
    }} />
  }
}

export default class Packets extends React.Component {
  constructor(props) {
    super(props);

    let list = Array.from(Object.values(this.props.trail.packets));
    let sortBy = 'index';
    let sortDirection = SortDirection.ASC;
    let sortedList = this._sortList(list, {sortBy, sortDirection});

    this.state = {
      sortBy: sortBy,
      sortDirection: sortDirection,
      sortedList: sortedList
    }

    this.rowGetter = this.rowGetter.bind(this);
    this._sort = this._sort.bind(this);
    this._sortList = this._sortList.bind(this);
  }

  rowGetter({ index }) {
    let item = this.state.sortedList[index];
    let date = moment(new Date(item['packet_sec'] * 1000));
    
    return {...item, timestamp: `${date.format("DD-MM-YYYY HH:mm")}`};
  }

  _sort({sortBy, sortDirection}) {
    const sortedList = this._sortList({sortBy, sortDirection});

    this.setState({sortBy, sortDirection, sortedList});
  }

  _sortList({sortBy, sortDirection}) {
    let list = Array.from(Object.values(this.props.trail.packets));

    let sortedList = list;
    
    if (sortBy !== 'index') {
      sortedList = sortedList.sort((a, b) => {
        if (typeof a[sortBy] === 'number') {
          return a[sortBy] - b[sortBy];
        }

        if (a[sortBy] < b[sortBy])
          return -1
        if (a[sortBy] > b[sortBy])
          return 1
        return 0
      });
    }

    if (sortDirection === SortDirection.DESC) {
      sortedList = sortedList.reverse();
    }

    return sortedList;
  }

  render() {
    let {
      sortBy,
      sortDirection
    } = this.state;
    
    return <div className="trails-table">
      <AutoSizer>
        {({ height, width }) => (
          <Table
            width={width}
            height={height}
            headerHeight={50}
            rowHeight={30}
            rowCount={this.state.sortedList.length}
            rowGetter={this.rowGetter.bind(this)}
            sort={this._sort}
            sortBy={sortBy}
            sortDirection={sortDirection}
            rowRenderer={rowRendererFactory(this.props.setSelectedTrail, this.props.trail.packets)}
          >
            <Column
              width={350}
              label='Timestamp'
              dataKey='timestamp'
            />
            <Column
              width={500}
              label='Trail'
              dataKey='trail'
            />
            <Column
              width={250}
              label='Type'
              dataKey='trail_type'
            />
            <Column
              width={250}
              label='Accuracy'
              dataKey='accuracy'
            />
            <Column
              width={250}
              label='Source'
              dataKey='src_ip'
            />
            <Column
              width={250}
              label='Port'
              dataKey='src_port'
            />
            <Column
              width={250}
              label='Destination'
              dataKey='dst_ip'
            />
            <Column
              width={250}
              label='Port'
              dataKey='dst_port'
            />
            <Column
              width={250}
              label='Reference'
              dataKey='reference'
            />
          </Table>
        )}
      </AutoSizer>
    </div>;
  }
}