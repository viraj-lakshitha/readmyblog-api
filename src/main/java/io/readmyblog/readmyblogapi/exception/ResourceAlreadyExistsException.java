package io.readmyblog.readmyblogapi.exception;

import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.sql.Time;
import java.util.Collections;

@NoArgsConstructor
@ResponseStatus(value = HttpStatus.CONFLICT)
public class ResourceAlreadyExistsException extends TimeEntryException {

    public ResourceAlreadyExistsException(String code, String identifier) {
        super(HttpStatus.CONFLICT, code, Collections.singletonMap("value", identifier));
    }

}
