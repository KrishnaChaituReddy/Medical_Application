package com.wecp.medicalequipmentandtrackingsystem.exceptions;

public class UsernameAlreadyExists extends RuntimeException{

    public UsernameAlreadyExists(String message){
        super(message);
    }

}
