package com.example.jwt.mapper;


import com.example.jwt.model.UserRecord;
import com.example.jwt.request.UserCreateRequest;

public class UserMapper {

    public static UserRecord mapToSave(UserCreateRequest user, String password){
        UserRecord userRecord = new UserRecord();
        userRecord.setFirstName(user.getFirstName());
        userRecord.setLastName(user.getLastName());
        userRecord.setEmail(user.getEmail());
        userRecord.setPassword(user.getPassword());
        userRecord.setDocument(user.getDocument());
        userRecord.setPhone(user.getPhone());
        userRecord.setPassword(password);
        userRecord.setStatus(true);
        return userRecord;
    }
}
