package io.readmyblog.readmyblogapi.exception;

import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.Collections;

@NoArgsConstructor
@ResponseStatus(value = HttpStatus.BAD_REQUEST)
public class BadRequestException extends TimeEntryException {

    public BadRequestException(String code) {
        this(code, null);
    }

    public BadRequestException(String code, String field) {
        super(HttpStatus.BAD_REQUEST, code, Collections.singletonMap("field", field));
    }

}
