package io.readmyblog.readmyblogapi.exception;

import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.HashMap;
import java.util.Map;

@NoArgsConstructor
@ResponseStatus(value = HttpStatus.BAD_REQUEST)
public class OperationNotAllowedException extends TimeEntryException {

    public OperationNotAllowedException(String code) {
        this(code, new HashMap<>());
    }

    public OperationNotAllowedException(String code, Map<String, Object> details) {
        super(HttpStatus.BAD_REQUEST, code, details);
    }

}
