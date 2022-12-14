package io.readmyblog.readmyblogapi.migration;

import com.github.cloudyrock.mongock.ChangeLog;
import com.github.cloudyrock.mongock.ChangeSet;
import com.github.cloudyrock.mongock.driver.mongodb.springdata.v3.decorator.impl.MongockTemplate;
import io.readmyblog.readmyblogapi.core.AuthProvider;
import io.readmyblog.readmyblogapi.core.Role;
import io.readmyblog.readmyblogapi.core.model.User;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

@ChangeLog(order = "001")
public class BaseDataMigrations {
    private final String USER_COLLECTION = "users";

    private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @ChangeSet(order = "001", id = "createSuperAdmin", author = "migrations")
    public void createSuperAdmin(MongockTemplate mongodbTemplate) {
        User user = new User();
        user.setName("Super Admin");
        user.setEmail("viraj@readmyblog.io");
        user.setProvider(AuthProvider.local);
        user.setPassword(passwordEncoder.encode("Viraj@104"));
        user.setRole(Role.ROLE_SUPER_ADMIN);
        mongodbTemplate.save(user, USER_COLLECTION);
    }

    @ChangeSet(order = "002", id = "updateUserCreatedAt", author = "migrations")
    public void updateUserCreatedAt(MongockTemplate mongoTemplate) throws ParseException {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd");
        Date date = format.parse("2022-02-21");

        Query queryUsers = Query.query(Criteria.where("createdAt").is(null));
        Update updatedUsers = Update.update("createdAt", date);
        mongoTemplate.updateMulti(queryUsers, updatedUsers, USER_COLLECTION);
    }
}