package io.readmyblog.readmyblogapi;

import com.github.cloudyrock.spring.v5.EnableMongock;
import io.readmyblog.readmyblogapi.configuration.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.data.mongodb.config.EnableMongoAuditing;

@EnableMongoAuditing
@EnableMongock
@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class ReadMyBlogApplication {

	public static void main(String[] args) {
		SpringApplication.run(ReadMyBlogApplication.class, args);
	}

}