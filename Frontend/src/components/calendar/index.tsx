import React,{Component} from 'react';
import { CFormLabel } from '@coreui/react';
import DatePicker from 'react-datepicker';
import 'react-datepicker/dist/react-datepicker.css';
import moment from "moment";
import {FontAwesomeIcon} from'@fortawesome/react-fontawesome';
import {faCalendar} from'@fortawesome/free-solid-svg-icons';

export interface CalendarProps {
    isShowlabel?:boolean;
    invalid?:boolean;
    onChange?:any;
    calendarContainer?:any;
    dateID?:string;
    label?:string;
    placeholder?:string;
    selectedValue:moment.Moment;
    minDate?:Date;
    maxDate?:Date;
    removeMargin?:boolean;
}

class Calendar extends Component<CalendarProps,any,any>{
    onChange=(selectedDate:any)=>{
        if(selectedDate===null||selectedDate===undefined)
            return;
        
            this.props.onChange(selectedDate);
    }
    render(){
        let selectedDate:Date|undefined = undefined;
        if(this.props.selectedValue){
            try{
                let selectedDate= this.props.selectedValue.toDate();
            } catch(e){
                selectedDate = (this.props.selectedValue as any);
            }
        }
    
    return<>
        {this.props.isShowLabel? (<cFormLabel htmlFor={this.props.dateID}>{this.props.label}</cFormLabel>):(null)}
        <div className={"controls flex-container date-picker-allign"+(this.props.removeMargin?" remove-margin":"")}>
            <div className="icon-container">
                <FontAwesomeIcon icon={faCalendar} className='calendar-icon'/>
            </div>
            <div className="date-picker-container">
                <DatePicker
                    id={this.props.dateID}
                    selected={selectedDate}
                    onChange
                    dateFormat="dd/MM/yyyy"
                    placeholderText={this.props.placeholder?this.props.placeholder:"dd/MM/yyyy"}
                    minDate={this.props.minDate? this.props.minDate:undefined}
                    maxDate={this.props.maxDate? this.props.maxDate: moment().toDate()}
                    calendarContainer={this.props.calendarContainer}
                    disabled={this.props.disabled}
                />
            </div>
        </div>
    </>;
    }
}
export default Calendar;